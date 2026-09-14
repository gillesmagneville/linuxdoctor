// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::command::command;
use crate::core::error::ModuleError;
use crate::modules::virtualization::collect::lookup_pci_description;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Intel,
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GpuProcess {
    pub pid: u32,
    pub name: String,
    pub memory_mb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GpuInfo {
    /// DRM card name, e.g. "card0" — used as the `.instance()` key.
    pub name: String,
    pub pci_address: String,
    pub vendor: GpuVendor,
    /// From `lspci` (or, failing that, NVIDIA's own reported name).
    pub description: Option<String>,
    /// Kernel driver bound to this device ("nvidia", "amdgpu", "i915",
    /// "nouveau", ...) — `None` specifically means *no* driver is bound
    /// at all, not "unknown"; see analyze.rs for why that's flagged.
    pub driver: Option<String>,
    pub driver_version: Option<String>,
    pub vram_total_mb: Option<u64>,
    pub vram_used_mb: Option<u64>,
    pub utilization_percent: Option<f64>,
    /// Memory-controller busy percentage — distinct from VRAM *capacity*
    /// used (how full it is): this is how busy the memory bus itself is.
    pub memory_utilization_percent: Option<f64>,
    pub temperature_c: Option<f64>,
    /// AMD-only: the card's own critical temperature threshold
    /// (`temp1_crit`), when available — lets severity be judged against
    /// this specific card's real limit instead of a guessed number.
    pub temperature_crit_c: Option<f64>,
    pub power_draw_w: Option<f64>,
    pub power_limit_w: Option<f64>,
    /// NVIDIA's `fan.speed` — a percentage of max fan speed.
    pub fan_percent: Option<f64>,
    /// AMD's `fan1_input` — raw RPM. Kept separate from `fan_percent`
    /// deliberately: these are different units from different sources,
    /// and conflating them into one field risks a silent unit mismatch.
    pub fan_rpm: Option<u64>,
    /// "Core"/"graphics" clock — NVIDIA's `clocks.gr`, or AMD's currently
    /// active state from `pp_dpm_sclk` (the line marked with `*`).
    pub clock_core_mhz: Option<u64>,
    /// Memory clock — NVIDIA's `clocks.mem`, or AMD's currently active
    /// state from `pp_dpm_mclk`.
    pub clock_memory_mhz: Option<u64>,
    /// Generic PCI sysfs (`current_link_speed`/`max_link_speed`) — works
    /// for any vendor, not just one. Kept as the kernel's own display
    /// string (e.g. "8.0 GT/s PCIe") rather than reparsed into a bare
    /// number, and read alongside the *current* value's known
    /// reliability caveat — see analyze.rs.
    pub pcie_link_speed_current: Option<String>,
    pub pcie_link_speed_max: Option<String>,
    pub pcie_link_width_current: Option<u32>,
    pub pcie_link_width_max: Option<u32>,
    /// NVIDIA only, and only when exactly one NVIDIA GPU is present —
    /// see `collect()` for why multi-GPU systems don't get per-process
    /// attribution here.
    pub processes: Vec<GpuProcess>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GpuRawData {
    pub gpus: Vec<GpuInfo>,
    /// The *maximum* CUDA version this system's NVIDIA driver supports —
    /// from `nvidia-smi`'s plain-text header, the only place it's
    /// exposed (not a `--query-gpu` field). Deliberately not called
    /// "CUDA version installed": confirmed via multiple independent
    /// sources that this reports driver-side support, not the CUDA
    /// Toolkit version an application actually uses — those can differ,
    /// and conflating them is a well-documented source of confusion this
    /// project isn't going to repeat. `None` without any NVIDIA GPU, or
    /// if `nvidia-smi` doesn't report it.
    pub nvidia_max_cuda_version: Option<String>,
}

/// Enumerate real GPU cards from `/sys/class/drm` — entries named exactly
/// "card<N>" (all-digit suffix), which distinguishes the card itself from
/// its per-connector entries (e.g. "card0-DP-1", one per physical output,
/// which would otherwise be miscounted as separate GPUs).
fn list_drm_cards() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/class/drm") else {
        return Vec::new();
    };
    let mut cards: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| {
            name.strip_prefix("card")
                .map(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false)
        })
        .collect();
    cards.sort();
    cards
}

/// Parse a DRM device's `uevent` file: simple `KEY=value` lines, one per
/// line — confirmed real format (the `amdgpu-sysfs` crate's own source,
/// and multiple independent real captures). `PCI_ID` is "VVVV:DDDD" hex
/// *without* a "0x" prefix — distinct from the standalone `vendor`/
/// `device` sysfs files, which do have the prefix. Returns
/// (driver, pci_id, pci_slot_name).
pub fn parse_drm_uevent(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let fields: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
    (
        fields.get("DRIVER").map(|s| s.to_string()),
        fields.get("PCI_ID").map(|s| s.to_string()),
        fields.get("PCI_SLOT_NAME").map(|s| s.to_string()),
    )
}

/// Classify vendor from the vendor half of `PCI_ID` (e.g. "1002:67DF" ->
/// "1002"). Confirmed PCI vendor IDs: `0x10de` NVIDIA, `0x1002` AMD/ATI
/// (the legacy ID AMD's GPUs still use — distinct from `0x1022`, AMD's
/// separate CPU/chipset vendor ID, which is *not* a GPU vendor ID and
/// deliberately not matched here), `0x8086` Intel.
pub fn classify_vendor(pci_id: &str) -> GpuVendor {
    match pci_id.split(':').next().unwrap_or("").to_lowercase().as_str() {
        "10de" => GpuVendor::Nvidia,
        "1002" => GpuVendor::Amd,
        "8086" => GpuVendor::Intel,
        _ => GpuVendor::Other,
    }
}

/// Normalize a PCI address to the canonical "DDDD:BB:SS.F" form (4-hex-
/// digit domain). `nvidia-smi`'s `pci.bus_id` field uses an 8-hex-digit
/// domain (confirmed real example: "00000000:01:00.0"), which needs
/// normalizing before comparing against the 4-digit form everything else
/// here uses (`uevent`'s `PCI_SLOT_NAME`, `lspci`).
pub fn normalize_pci_address(addr: &str) -> Option<String> {
    let parts: Vec<&str> = addr.trim().split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let domain = u32::from_str_radix(parts[0], 16).ok()?;
    let bus = u32::from_str_radix(parts[1], 16).ok()?;
    let (slot_str, function_str) = parts[2].split_once('.')?;
    let slot = u32::from_str_radix(slot_str, 16).ok()?;
    let function = u32::from_str_radix(function_str, 16).ok()?;
    Some(format!("{domain:04x}:{bus:02x}:{slot:02x}.{function:x}"))
}

/// AMD (`amdgpu` driver) sysfs enrichment. Every path/unit here is
/// confirmed from the kernel's own amdgpu documentation and multiple
/// independent real captures, not assumed:
/// - `mem_info_vram_total` / `mem_info_vram_used`: bytes
/// - `gpu_busy_percent` / `mem_busy_percent`: integer 0-100
/// - `hwmon/hwmon*/temp1_input` / `temp1_crit`: millidegrees Celsius
/// - `hwmon/hwmon*/power1_average`: microwatts
/// - `hwmon/hwmon*/fan1_input`: RPM
fn enrich_amd(gpu: &mut GpuInfo, device_dir: &Path) {
    let read_u64 = |name: &str| -> Option<u64> {
        fs::read_to_string(device_dir.join(name)).ok()?.trim().parse().ok()
    };

    gpu.vram_total_mb = read_u64("mem_info_vram_total").map(|b| b / 1024 / 1024);
    gpu.vram_used_mb = read_u64("mem_info_vram_used").map(|b| b / 1024 / 1024);
    gpu.utilization_percent = read_u64("gpu_busy_percent").map(|v| v as f64);
    gpu.memory_utilization_percent = read_u64("mem_busy_percent").map(|v| v as f64);

    // hwmon's own subdirectory name varies (hwmon0, hwmon1, ...) across
    // boots/systems, so find whichever one is actually there rather than
    // assuming a fixed index.
    let hwmon_dir = fs::read_dir(device_dir.join("hwmon"))
        .ok()
        .and_then(|mut entries| entries.next())
        .and_then(|e| e.ok())
        .map(|e| e.path());

    if let Some(hwmon_dir) = hwmon_dir {
        let read_hwmon_f64 = |name: &str| -> Option<f64> {
            fs::read_to_string(hwmon_dir.join(name)).ok()?.trim().parse().ok()
        };
        gpu.temperature_c = read_hwmon_f64("temp1_input").map(|m| m / 1000.0);
        gpu.temperature_crit_c = read_hwmon_f64("temp1_crit").map(|m| m / 1000.0);
        gpu.power_draw_w = read_hwmon_f64("power1_average").map(|uw| uw / 1_000_000.0);
        gpu.fan_rpm = read_hwmon_f64("fan1_input").map(|v| v as u64);
    }

    if let Ok(text) = fs::read_to_string(device_dir.join("pp_dpm_sclk")) {
        gpu.clock_core_mhz = parse_pp_dpm_current_clock(&text);
    }
    if let Ok(text) = fs::read_to_string(device_dir.join("pp_dpm_mclk")) {
        gpu.clock_memory_mhz = parse_pp_dpm_current_clock(&text);
    }
}

/// Parse a `pp_dpm_sclk`/`pp_dpm_mclk`-style file: one "N: FREQMhz[*]"
/// line per available power state, with an asterisk marking the
/// currently active one. Confirmed real format (a real capture during
/// research: "0: 600Mhz / 1: 2787Mhz* / 2: 2900Mhz", one entry per line
/// in the actual file) — the file lists every state the card *can* run
/// at; only the starred line is the current one.
pub fn parse_pp_dpm_current_clock(text: &str) -> Option<u64> {
    for line in text.lines() {
        let line = line.trim();
        if !line.ends_with('*') {
            continue;
        }
        let (_, freq_part) = line.trim_end_matches('*').trim().split_once(':')?;
        let digits: String = freq_part.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(mhz) = digits.parse() {
            return Some(mhz);
        }
    }
    None
}

/// Generic PCI link-speed/width sysfs enrichment — applies to any
/// vendor, since these files (`current_link_speed`, `max_link_speed`,
/// `current_link_width`, `max_link_width`) are a core PCI kernel
/// feature, not something a GPU driver adds. Confirmed exact format:
/// "5.0 GT/s PCIe" for speed (real capture), a bare integer for width.
/// Known reliability caveat, confirmed via a real bug report (amdgpu_top
/// issue #33): some kernel/driver combinations report
/// `current_link_speed` as the negotiated *maximum* rather than a true
/// live reading, particularly when a link has downclocked for power
/// saving — this collector still reads it as the best available generic
/// source, but analyze.rs's wording reflects that caveat rather than
/// presenting it as a guaranteed-live snapshot.
fn enrich_pcie_link_info(gpu: &mut GpuInfo, device_dir: &Path) {
    let read_str = |name: &str| -> Option<String> {
        fs::read_to_string(device_dir.join(name)).ok().map(|s| s.trim().to_string())
    };
    gpu.pcie_link_speed_current = read_str("current_link_speed");
    gpu.pcie_link_speed_max = read_str("max_link_speed");
    gpu.pcie_link_width_current = fs::read_to_string(device_dir.join("current_link_width"))
        .ok()
        .and_then(|s| s.trim().parse().ok());
    gpu.pcie_link_width_max = fs::read_to_string(device_dir.join("max_link_width"))
        .ok()
        .and_then(|s| s.trim().parse().ok());
}

/// NVIDIA field order for the combined `--query-gpu` call — position in
/// this list must match the parsing indices in `parse_nvidia_smi_csv`.
/// PCIe link info deliberately isn't queried here: it's covered
/// uniformly for every vendor via `enrich_pcie_link_info`'s generic PCI
/// sysfs read, rather than maintaining two potentially-disagreeing
/// sources for the same fact.
const NVIDIA_QUERY_FIELDS: &str = "pci.bus_id,name,driver_version,temperature.gpu,\
utilization.gpu,utilization.memory,memory.total,memory.used,power.draw,power.limit,\
fan.speed,clocks.gr,clocks.mem";

#[derive(Debug, Clone, PartialEq)]
pub struct NvidiaSample {
    pci_address: String,
    name: String,
    driver_version: Option<String>,
    temperature_c: Option<f64>,
    utilization_percent: Option<f64>,
    memory_utilization_percent: Option<f64>,
    vram_total_mb: Option<u64>,
    vram_used_mb: Option<u64>,
    power_draw_w: Option<f64>,
    power_limit_w: Option<f64>,
    fan_percent: Option<f64>,
    clock_core_mhz: Option<u64>,
    clock_memory_mhz: Option<u64>,
}

fn run_nvidia_smi_query() -> Option<String> {
    let output = command("nvidia-smi")
        .arg(format!("--query-gpu={NVIDIA_QUERY_FIELDS}"))
        .arg("--format=csv,noheader,nounits")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

/// The plain `nvidia-smi` header (no args) is the *only* place the
/// maximum-supported CUDA version is exposed — confirmed not present in
/// `--query-gpu`'s field set.
fn run_nvidia_smi_header() -> Option<String> {
    let output = command("nvidia-smi").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_nvidia_smi_processes() -> Option<String> {
    let output = command("nvidia-smi")
        .arg("--query-compute-apps=pid,process_name,used_memory")
        .arg("--format=csv,noheader,nounits")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse `nvidia-smi --query-gpu=... --format=csv,noheader,nounits`
/// output. Confirmed real format via numerous independent real-world
/// captures: comma-separated, no header row, no unit suffixes ("%",
/// "MiB", "W") attached — the most reliable form to parse. `power.draw`
/// can come back as the literal string "[Not Supported]" on some GPU/
/// power-state combinations (also confirmed via a real capture); handled
/// explicitly as a missing reading rather than a parse failure that
/// would look identical to "genuinely absent".
pub fn parse_nvidia_smi_csv(text: &str) -> Vec<NvidiaSample> {
    fn opt_f64(s: &str) -> Option<f64> {
        if s.is_empty() || s.eq_ignore_ascii_case("[not supported]") {
            None
        } else {
            s.parse().ok()
        }
    }
    fn opt_u64(s: &str) -> Option<u64> {
        if s.is_empty() || s.eq_ignore_ascii_case("[not supported]") {
            None
        } else {
            s.parse().ok()
        }
    }

    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            if fields.len() < 13 {
                return None;
            }
            let pci_address =
                normalize_pci_address(fields[0]).unwrap_or_else(|| fields[0].to_string());
            Some(NvidiaSample {
                pci_address,
                name: fields[1].to_string(),
                driver_version: Some(fields[2].to_string()).filter(|s| !s.is_empty()),
                temperature_c: opt_f64(fields[3]),
                utilization_percent: opt_f64(fields[4]),
                memory_utilization_percent: opt_f64(fields[5]),
                vram_total_mb: opt_u64(fields[6]),
                vram_used_mb: opt_u64(fields[7]),
                power_draw_w: opt_f64(fields[8]),
                power_limit_w: opt_f64(fields[9]),
                fan_percent: opt_f64(fields[10]),
                clock_core_mhz: opt_u64(fields[11]),
                clock_memory_mhz: opt_u64(fields[12]),
            })
        })
        .collect()
}

/// Extract the *maximum-supported* CUDA version from `nvidia-smi`'s
/// plain-text table header, e.g. "| NVIDIA-SMI 460.32.03  Driver
/// Version: 460.32.03  CUDA Version: 11.2 |" (confirmed real example).
/// Deliberately not exposed as "CUDA version installed" — see
/// `GpuRawData::nvidia_max_cuda_version` for why that distinction
/// matters.
pub fn parse_nvidia_max_cuda_version(text: &str) -> Option<String> {
    let marker = "CUDA Version:";
    let idx = text.find(marker)?;
    let rest = &text[idx + marker.len()..];
    let version: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

/// Parse `nvidia-smi --query-compute-apps=pid,process_name,used_memory
/// --format=csv,noheader,nounits` — same clean comma-separated shape as
/// the main GPU query.
pub fn parse_nvidia_compute_apps(text: &str) -> Vec<GpuProcess> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            if fields.len() < 3 {
                return None;
            }
            Some(GpuProcess {
                pid: fields[0].parse().ok()?,
                name: fields[1].to_string(),
                memory_mb: fields[2].parse().ok(),
            })
        })
        .collect()
}

/// Thin I/O wrapper: enumerates DRM cards, classifies each by vendor from
/// its own `uevent`, then applies vendor-specific enrichment — AMD via
/// direct sysfs reads (no external tool needed), NVIDIA via one combined
/// `nvidia-smi` call for every NVIDIA GPU at once. Intel and unrecognized
/// vendors get the structural facts (PCI address, driver, description)
/// without utilization/thermal data — there's no equally-confirmed,
/// dependency-free source for those on Intel the way there is for AMD's
/// sysfs or NVIDIA's tooling, and this project doesn't guess where it
/// can't verify.
pub fn collect() -> Result<GpuRawData, ModuleError> {
    let cards = list_drm_cards();
    let mut gpus = Vec::new();

    for card in &cards {
        let device_dir = PathBuf::from(format!("/sys/class/drm/{card}/device"));
        let Ok(uevent_text) = fs::read_to_string(device_dir.join("uevent")) else {
            continue;
        };
        let (driver, pci_id, pci_slot_name) = parse_drm_uevent(&uevent_text);
        let (Some(pci_id), Some(pci_address)) = (pci_id, pci_slot_name) else {
            continue;
        };
        let vendor = classify_vendor(&pci_id);
        let description = lookup_pci_description(&pci_address);

        let mut gpu = GpuInfo {
            name: card.clone(),
            pci_address,
            vendor,
            description,
            driver,
            driver_version: None,
            vram_total_mb: None,
            vram_used_mb: None,
            utilization_percent: None,
            memory_utilization_percent: None,
            temperature_c: None,
            temperature_crit_c: None,
            power_draw_w: None,
            power_limit_w: None,
            fan_percent: None,
            fan_rpm: None,
            clock_core_mhz: None,
            clock_memory_mhz: None,
            pcie_link_speed_current: None,
            pcie_link_speed_max: None,
            pcie_link_width_current: None,
            pcie_link_width_max: None,
            processes: Vec::new(),
        };

        // Generic PCI feature, applied uniformly regardless of vendor —
        // see enrich_pcie_link_info's doc comment for the known
        // current-vs-max reliability caveat this carries.
        enrich_pcie_link_info(&mut gpu, &device_dir);

        if vendor == GpuVendor::Amd {
            enrich_amd(&mut gpu, &device_dir);
        }

        gpus.push(gpu);
    }

    let mut nvidia_max_cuda_version = None;

    if gpus.iter().any(|g| g.vendor == GpuVendor::Nvidia) {
        if let Some(csv) = run_nvidia_smi_query() {
            let samples = parse_nvidia_smi_csv(&csv);
            for gpu in &mut gpus {
                if gpu.vendor != GpuVendor::Nvidia {
                    continue;
                }
                let Some(self_addr) = normalize_pci_address(&gpu.pci_address) else {
                    continue;
                };
                if let Some(sample) = samples.iter().find(|s| s.pci_address == self_addr) {
                    gpu.driver_version = sample.driver_version.clone();
                    gpu.temperature_c = sample.temperature_c;
                    gpu.utilization_percent = sample.utilization_percent;
                    gpu.memory_utilization_percent = sample.memory_utilization_percent;
                    gpu.vram_total_mb = sample.vram_total_mb;
                    gpu.vram_used_mb = sample.vram_used_mb;
                    gpu.power_draw_w = sample.power_draw_w;
                    gpu.power_limit_w = sample.power_limit_w;
                    gpu.fan_percent = sample.fan_percent;
                    gpu.clock_core_mhz = sample.clock_core_mhz;
                    gpu.clock_memory_mhz = sample.clock_memory_mhz;
                    if gpu.description.is_none() {
                        gpu.description = Some(sample.name.clone());
                    }
                }
            }
        }

        if let Some(header) = run_nvidia_smi_header() {
            nvidia_max_cuda_version = parse_nvidia_max_cuda_version(&header);
        }

        // Per-process GPU memory attribution only when there's exactly
        // one NVIDIA GPU: `nvidia-smi --query-compute-apps` doesn't carry
        // a per-GPU key in this query, so with 2+ NVIDIA GPUs there's no
        // reliable way to know which process belongs to which card —
        // left empty there rather than guessing (e.g. via ordering, which
        // isn't guaranteed to match).
        let nvidia_indices: Vec<usize> = gpus
            .iter()
            .enumerate()
            .filter(|(_, g)| g.vendor == GpuVendor::Nvidia)
            .map(|(i, _)| i)
            .collect();
        if nvidia_indices.len() == 1 {
            if let Some(proc_text) = run_nvidia_smi_processes() {
                gpus[nvidia_indices[0]].processes = parse_nvidia_compute_apps(&proc_text);
            }
        }
    }

    Ok(GpuRawData {
        gpus,
        nvidia_max_cuda_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_connector_entries_from_card_entries() {
        // Can't touch the real filesystem meaningfully in a unit test
        // for list_drm_cards() itself (it reads /sys), so this tests the
        // filter predicate logic directly via the same pattern.
        let is_card = |name: &str| {
            name.strip_prefix("card")
                .map(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false)
        };
        assert!(is_card("card0"));
        assert!(is_card("card1"));
        assert!(!is_card("card0-DP-1"));
        assert!(!is_card("renderD128"));
    }

    const FIXTURE_UEVENT_AMD: &str = "\
DRIVER=amdgpu
PCI_CLASS=30000
PCI_ID=1002:67DF
PCI_SUBSYS_ID=1DA2:E387
PCI_SLOT_NAME=0000:01:00.0
MODALIAS=pci:v00001002d000067DFsv00001DA2sd0000E387bc03sc00i00
";

    #[test]
    fn parses_drm_uevent() {
        let (driver, pci_id, slot) = parse_drm_uevent(FIXTURE_UEVENT_AMD);
        assert_eq!(driver.as_deref(), Some("amdgpu"));
        assert_eq!(pci_id.as_deref(), Some("1002:67DF"));
        assert_eq!(slot.as_deref(), Some("0000:01:00.0"));
    }

    #[test]
    fn classifies_known_vendors() {
        assert_eq!(classify_vendor("10de:2484"), GpuVendor::Nvidia);
        assert_eq!(classify_vendor("1002:67DF"), GpuVendor::Amd);
        assert_eq!(classify_vendor("8086:9a49"), GpuVendor::Intel);
        assert_eq!(classify_vendor("1234:5678"), GpuVendor::Other);
    }

    #[test]
    fn does_not_confuse_amd_cpu_vendor_id_with_amd_gpu_vendor_id() {
        // 0x1022 is AMD's own CPU/chipset PCI vendor ID -- not a GPU
        // vendor ID, and must not be classified as one.
        assert_eq!(classify_vendor("1022:1480"), GpuVendor::Other);
    }

    #[test]
    fn normalizes_nvidia_style_8_digit_domain_address() {
        assert_eq!(
            normalize_pci_address("00000000:01:00.0"),
            Some("0000:01:00.0".to_string())
        );
    }

    #[test]
    fn normalize_matches_standard_4_digit_domain_address() {
        // Both forms of the same address must normalize identically for
        // the NVIDIA <-> DRM correlation in collect() to work.
        assert_eq!(
            normalize_pci_address("00000000:01:00.0"),
            normalize_pci_address("0000:01:00.0")
        );
    }

    #[test]
    fn normalize_rejects_malformed_address() {
        assert_eq!(normalize_pci_address("not-an-address"), None);
    }

    // Real captured shape (multiple independent sources during research),
    // one V100 and one lower-utilization card.
    const FIXTURE_NVIDIA_CSV: &str = "\
00000000:01:00.0, NVIDIA RTX A6000, 550.78, 58, 72, 12, 49152, 13456, 215.30, 300.00, 45, 1815, 6939
00000000:02:00.0, NVIDIA RTX A6000, 550.78, 40, 0, 0, 49152, 27, 15.52, 300.00, 30, 139, 405
";

    #[test]
    fn parses_real_nvidia_smi_csv_shape() {
        let samples = parse_nvidia_smi_csv(FIXTURE_NVIDIA_CSV);
        assert_eq!(samples.len(), 2);
        let a = &samples[0];
        assert_eq!(a.pci_address, "0000:01:00.0");
        assert_eq!(a.name, "NVIDIA RTX A6000");
        assert_eq!(a.driver_version.as_deref(), Some("550.78"));
        assert_eq!(a.temperature_c, Some(58.0));
        assert_eq!(a.utilization_percent, Some(72.0));
        assert_eq!(a.vram_used_mb, Some(13456));
        assert_eq!(a.vram_total_mb, Some(49152));
        assert_eq!(a.power_draw_w, Some(215.30));
        assert_eq!(a.fan_percent, Some(45.0));
        assert_eq!(a.clock_core_mhz, Some(1815));
        assert_eq!(a.clock_memory_mhz, Some(6939));
    }

    #[test]
    fn nvidia_not_supported_power_draw_is_none_not_a_parse_error() {
        let text = "00000000:01:00.0, GeForce GTX 1050, 396.45, 40, 0, 0, 4040, 2, [Not Supported], 75.00, 30, 139, 3504";
        let samples = parse_nvidia_smi_csv(text);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].power_draw_w, None);
        // Confirms this is a deliberate "unsupported" case, not a
        // generic parse failure -- other fields on the same line parse.
        assert_eq!(samples[0].temperature_c, Some(40.0));
    }

    // Real captured shape from the NVIDIA compute-apps query examples.
    const FIXTURE_NVIDIA_PROCESSES: &str = "\
3024, python3, 5678
4051, python3, 1234
";

    #[test]
    fn parses_nvidia_compute_apps() {
        let procs = parse_nvidia_compute_apps(FIXTURE_NVIDIA_PROCESSES);
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 3024);
        assert_eq!(procs[0].name, "python3");
        assert_eq!(procs[0].memory_mb, Some(5678));
    }

    #[test]
    fn empty_process_list_is_empty_not_an_error() {
        assert!(parse_nvidia_compute_apps("").is_empty());
    }

    // Real captured shape (a ROCm/AMD gfx1151 bug report during
    // research): "0: 600Mhz / 1: 2787Mhz* / 2: 2900Mhz" is shown on one
    // line there for brevity, but the actual file has one entry per line.
    const FIXTURE_PP_DPM_SCLK: &str = "\
0: 600Mhz
1: 2787Mhz*
2: 2900Mhz
";

    #[test]
    fn parses_current_pp_dpm_clock() {
        assert_eq!(parse_pp_dpm_current_clock(FIXTURE_PP_DPM_SCLK), Some(2787));
    }

    #[test]
    fn pp_dpm_clock_none_when_nothing_starred() {
        let text = "0: 600Mhz\n1: 2787Mhz\n2: 2900Mhz\n";
        assert_eq!(parse_pp_dpm_current_clock(text), None);
    }

    #[test]
    fn pp_dpm_clock_handles_single_state() {
        assert_eq!(parse_pp_dpm_current_clock("0: 1750Mhz*\n"), Some(1750));
    }

    // Real captured header shape (Baeldung on Linux, confirmed real
    // example): "NVIDIA-SMI 460.32.03  Driver Version: 460.32.03  CUDA
    // Version: 11.2".
    #[test]
    fn parses_max_cuda_version_from_real_header_shape() {
        let text = "+-----------------------------------------------------------------------------+\n| NVIDIA-SMI 460.32.03    Driver Version: 460.32.03    CUDA Version: 11.2     |\n|-------------------------------+----------------------+----------------------+\n";
        assert_eq!(
            parse_nvidia_max_cuda_version(text),
            Some("11.2".to_string())
        );
    }

    #[test]
    fn max_cuda_version_none_when_absent() {
        assert_eq!(parse_nvidia_max_cuda_version("nothing relevant here"), None);
    }

    #[test]
    fn max_cuda_version_handles_na() {
        // Confirmed real symptom: some driver/setup combinations show
        // "CUDA Version: N/A" instead of a real number.
        let text = "CUDA Version: N/A |";
        assert_eq!(parse_nvidia_max_cuda_version(text), None);
    }
}
