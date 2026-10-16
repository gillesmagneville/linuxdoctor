// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::command::ToolSession;
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
    /// DRM card name, e.g. "card0" — used as the `.instance()` key. For a GPU
    /// the kernel exposes no DRM card for (`drm_card == false`), its PCI
    /// address instead.
    pub name: String,
    pub pci_address: String,
    pub vendor: GpuVendor,
    /// Whether the kernel exposes a DRM card (`/sys/class/drm/cardN`) for
    /// this GPU. `false` for a GPU only found on the PCI bus: one reserved
    /// for VM passthrough (`vfio-pci`), one with no driver, or a compute
    /// GPU whose driver registers no graphics card. Such a GPU has no
    /// sysfs readings beyond its PCIe link.
    pub drm_card: bool,
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
    /// Intel only: the highest frequency the hardware can run at (i915
    /// `RP0`, xe `rp0_freq`).
    pub clock_hw_max_mhz: Option<u64>,
    /// Intel only: the highest frequency the driver is currently allowed to
    /// use (i915 `rps_max_freq_mhz`, xe `max_freq`). Lower than
    /// `clock_hw_max_mhz` means a cap was set by someone or something.
    pub clock_limit_mhz: Option<u64>,
    /// Intel only: `Some(true)` when the driver reported an actual
    /// frequency of 0 MHz. It does that when the GPU is asleep in its
    /// power-saving state (the i915 code only reads the real value while
    /// the device is in use), so 0 means "idle", not "clocked at 0 MHz" --
    /// `clock_core_mhz` is left empty in that case.
    pub idle: Option<bool>,
    /// Intel only: whether the driver says the GPU is being held below its
    /// target frequency at this very moment. `None` when it doesn't say.
    pub throttled: Option<bool>,
    /// Intel only: the kernel's own names for what is holding the GPU back
    /// ("pl1", "thermal", ...), see `INTEL_THROTTLE_REASONS`. Empty when not
    /// throttled, or when the driver doesn't list reasons.
    pub throttle_reasons: Vec<String>,
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

impl GpuInfo {
    /// A GPU with its identity and nothing measured yet.
    pub fn new(
        name: String,
        pci_address: String,
        vendor: GpuVendor,
        description: Option<String>,
        driver: Option<String>,
        drm_card: bool,
    ) -> GpuInfo {
        GpuInfo {
            name,
            pci_address,
            vendor,
            drm_card,
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
            clock_hw_max_mhz: None,
            clock_limit_mhz: None,
            idle: None,
            throttled: None,
            throttle_reasons: Vec::new(),
            pcie_link_speed_current: None,
            pcie_link_speed_max: None,
            pcie_link_width_current: None,
            pcie_link_width_max: None,
            processes: Vec::new(),
        }
    }
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
    match pci_id
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
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
        fs::read_to_string(device_dir.join(name))
            .ok()?
            .trim()
            .parse()
            .ok()
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
            fs::read_to_string(hwmon_dir.join(name))
                .ok()?
                .trim()
                .parse()
                .ok()
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
        let digits: String = freq_part
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
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
        fs::read_to_string(device_dir.join(name))
            .ok()
            .map(|s| s.trim().to_string())
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

/// What an Intel GPU's throttle reasons are called in the i915 driver: one
/// `throttle_reason_<name>` file (holding 0 or 1) per name, under `gt/gt0/`.
/// The xe driver lists the same names in its `throttle/reasons` file (plus a
/// few more on data-centre parts, which are kept as they come).
const INTEL_THROTTLE_REASONS: [&str; 8] = [
    "pl1",
    "pl2",
    "pl4",
    "thermal",
    "prochot",
    "ratl",
    "vr_thermalert",
    "vr_tdc",
];

/// The `name` the Intel drivers give their hwmon chip.
const INTEL_HWMON_NAMES: [&str; 2] = ["i915", "xe"];

/// Longest reason name and longest list accepted from a driver's own list.
const MAX_REASON_NAME_LEN: usize = 24;
const MAX_REASONS: usize = 12;

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_number<T: std::str::FromStr>(path: &Path) -> Option<T> {
    read_trimmed(path)?.parse().ok()
}

/// A sysfs boolean: `1` or `0`, nothing else.
pub fn parse_flag(text: &str) -> Option<bool> {
    match text.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

fn read_flag(path: &Path) -> Option<bool> {
    parse_flag(&fs::read_to_string(path).ok()?)
}

/// Parse the xe driver's `freq0/throttle/reasons`: names separated by spaces
/// (with a trailing space), or the single word `none` -- confirmed in the
/// kernel's `xe_gt_throttle.c`. Only plain lowercase names are kept: they
/// end up in a report, and a name that isn't one is not worth showing.
pub fn parse_throttle_reasons(text: &str) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    for token in text.split_whitespace() {
        let token = token.to_ascii_lowercase();
        let plain = !token.is_empty()
            && token.len() <= MAX_REASON_NAME_LEN
            && token
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if token == "none" || !plain || reasons.contains(&token) {
            continue;
        }
        if reasons.len() < MAX_REASONS {
            reasons.push(token);
        }
    }
    reasons
}

/// Does this throttle reason come from temperature? `thermal`, `ratl` (the
/// running-average thermal limit), `vr_thermalert`, and the `*_thermal`
/// names of the data-centre parts. `prochot` is deliberately left out: it is
/// an external "hot" signal that the kernel doesn't tie to temperature.
pub fn is_thermal_throttle_reason(name: &str) -> bool {
    name == "ratl" || name.contains("thermal")
}

/// Combine the overall status with the list of reasons. The two are read at
/// slightly different moments, so a reason seen is taken as proof of
/// throttling even if the status read a moment earlier said otherwise.
fn settle_throttle(status: Option<bool>, reasons: Vec<String>) -> (Option<bool>, Vec<String>) {
    let throttled = match status {
        Some(true) => Some(true),
        _ if !reasons.is_empty() => Some(true),
        Some(false) => Some(false),
        None => None,
    };
    (throttled, reasons)
}

/// The Intel driver's hwmon directory under a device, whichever number the
/// kernel gave it -- found by its `name` rather than by position, since a
/// device can have more than one hwmon chip.
fn find_intel_hwmon(device_dir: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(device_dir.join("hwmon"))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    dirs.sort();
    dirs.into_iter().find(|dir| {
        read_trimmed(&dir.join("name")).is_some_and(|n| INTEL_HWMON_NAMES.contains(&n.as_str()))
    })
}

fn apply_intel_frequencies(
    gpu: &mut GpuInfo,
    actual: Option<u64>,
    hw_max: Option<u64>,
    limit: Option<u64>,
) {
    match actual {
        Some(0) => gpu.idle = Some(true),
        Some(mhz) => {
            gpu.clock_core_mhz = Some(mhz);
            gpu.idle = Some(false);
        }
        None => {}
    }
    gpu.clock_hw_max_mhz = hw_max.filter(|&mhz| mhz > 0);
    gpu.clock_limit_mhz = limit.filter(|&mhz| mhz > 0);
}

/// Intel (`i915` and `xe` drivers) sysfs enrichment. Paths, units and
/// formats come from the kernel's own sources and ABI documentation
/// (`intel_gt_sysfs_pm.c`, `i915_hwmon.c`, `xe_gt_freq.c`,
/// `xe_gt_throttle.c`, `Documentation/ABI/testing/sysfs-driver-intel-*-hwmon`),
/// not from guesswork. They have not been exercised on real Intel
/// hardware by this project -- which is why every read is optional and a
/// missing file simply leaves the field empty.
///
/// `card_dir` is `/sys/class/drm/cardN`: the i915 driver puts its frequency
/// files there (`gt/gt0/` on current kernels, `gt_*_freq_mhz` on older
/// ones), the xe driver and both hwmon chips live under its `device/`.
/// Only the first graphics GT (`gt0`) is read -- media GTs on recent parts
/// have their own frequency, which this doesn't try to report.
fn enrich_intel(gpu: &mut GpuInfo, card_dir: &Path) {
    let device_dir = card_dir.join("device");
    match gpu.driver.as_deref() {
        Some("i915") => enrich_intel_i915(gpu, card_dir),
        Some("xe") => enrich_intel_xe(gpu, &device_dir),
        // Another driver (or none): nothing Intel-specific to read.
        _ => return,
    }
    enrich_intel_hwmon(gpu, &device_dir);
}

/// i915: `rps_*_freq_mhz` are decimal MHz. `rps_act_freq_mhz` is the real
/// frequency, 0 while the device is asleep; `cur` is deliberately not used,
/// it is only what was last *requested*.
fn enrich_intel_i915(gpu: &mut GpuInfo, card_dir: &Path) {
    let gt = card_dir.join("gt").join("gt0");
    if gt.is_dir() {
        apply_intel_frequencies(
            gpu,
            read_number(&gt.join("rps_act_freq_mhz")),
            read_number(&gt.join("rps_RP0_freq_mhz")),
            read_number(&gt.join("rps_max_freq_mhz")),
        );
        let status = read_flag(&gt.join("throttle_reason_status"));
        let reasons: Vec<String> = INTEL_THROTTLE_REASONS
            .iter()
            .filter(|name| read_flag(&gt.join(format!("throttle_reason_{name}"))) == Some(true))
            .map(|name| name.to_string())
            .collect();
        (gpu.throttled, gpu.throttle_reasons) = settle_throttle(status, reasons);
    } else {
        // Kernels before the per-GT layout: same values, flat names.
        apply_intel_frequencies(
            gpu,
            read_number(&card_dir.join("gt_act_freq_mhz")),
            read_number(&card_dir.join("gt_RP0_freq_mhz")),
            read_number(&card_dir.join("gt_max_freq_mhz")),
        );
    }
}

/// xe: `tile0/gt0/freq0/*_freq` are decimal MHz. `cur_freq` is not read: the
/// kernel takes a forcewake (wakes the GPU up) to answer it, which a
/// read-only audit has no business doing. `act_freq` can be 0 in the
/// power-saving state.
fn enrich_intel_xe(gpu: &mut GpuInfo, device_dir: &Path) {
    let freq = device_dir.join("tile0").join("gt0").join("freq0");
    apply_intel_frequencies(
        gpu,
        read_number(&freq.join("act_freq")),
        read_number(&freq.join("rp0_freq")),
        read_number(&freq.join("max_freq")),
    );
    let throttle = freq.join("throttle");
    let status = read_flag(&throttle.join("status"));
    let reasons = fs::read_to_string(throttle.join("reasons"))
        .map(|text| parse_throttle_reasons(&text))
        .unwrap_or_default();
    (gpu.throttled, gpu.throttle_reasons) = settle_throttle(status, reasons);
}

/// Temperature, fan and power limit from the driver's hwmon chip. Only
/// discrete cards have one under i915; xe's package temperature needs
/// kernel 6.15 (its critical threshold 7.0) and its fan 6.16. Integrated
/// GPUs show none of this, and that's normal.
///
/// Units, per the hwmon ABI: `temp*` in millidegrees Celsius, `fan*` in
/// RPM, `power1_max` in microwatts (0 meaning the limit is disabled).
fn enrich_intel_hwmon(gpu: &mut GpuInfo, device_dir: &Path) {
    let Some(hwmon) = find_intel_hwmon(device_dir) else {
        return;
    };
    // i915 numbers its package temperature 1; xe numbers it 2.
    let temp = if gpu.driver.as_deref() == Some("xe") {
        "temp2"
    } else {
        "temp1"
    };
    gpu.temperature_c =
        read_number::<f64>(&hwmon.join(format!("{temp}_input"))).map(|m| m / 1000.0);
    gpu.temperature_crit_c = read_number::<f64>(&hwmon.join(format!("{temp}_crit")))
        .map(|m| m / 1000.0)
        .filter(|&c| c > 0.0);
    gpu.fan_rpm = read_number(&hwmon.join("fan1_input"));
    gpu.power_limit_w = read_number::<f64>(&hwmon.join("power1_max"))
        .map(|uw| uw / 1_000_000.0)
        .filter(|&w| w > 0.0);
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

/// A display-class PCI device as found on the PCI bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciDisplayDevice {
    /// Canonical "DDDD:BB:SS.F" address.
    pub address: String,
    pub vendor: GpuVendor,
    /// Kernel driver bound to it (the `driver` symlink's target name), or
    /// `None` when nothing is bound.
    pub driver: Option<String>,
    /// `/sys/bus/pci/devices/<address>`.
    pub dir: PathBuf,
}

/// Parse a PCI device's `class` file: `0x` and six hex digits, e.g.
/// `0x030000` (confirmed format of the kernel's PCI sysfs).
pub fn parse_pci_class(text: &str) -> Option<u32> {
    u32::from_str_radix(text.trim().strip_prefix("0x")?, 16).ok()
}

/// Is this PCI class a display controller? Base class `0x03`: VGA
/// (`0x0300`), 3D controller (`0x0302`, what NVIDIA's compute-only cards
/// report) and other display controller (`0x0380`). Audio functions
/// (`0x04xx`) and bridges (`0x06xx`) on the same card are not.
pub fn is_display_class(class: u32) -> bool {
    class >> 16 == 0x03
}

/// Every display-class PCI device under `pci_root` (normally
/// `/sys/bus/pci/devices`), sorted by address. SR-IOV virtual functions
/// (they have a `physfn` link) are left out: a host sharing one GPU among
/// many virtual functions would otherwise report each as a GPU of its own.
pub fn scan_pci_display_devices(pci_root: &Path) -> Vec<PciDisplayDevice> {
    let Ok(entries) = fs::read_dir(pci_root) else {
        return Vec::new();
    };
    let mut devices: Vec<PciDisplayDevice> = entries
        .flatten()
        .filter_map(|entry| {
            let dir = entry.path();
            let address = normalize_pci_address(entry.file_name().to_str()?)?;
            let class = parse_pci_class(&fs::read_to_string(dir.join("class")).ok()?)?;
            if !is_display_class(class) || dir.join("physfn").exists() {
                return None;
            }
            let vendor = read_trimmed(&dir.join("vendor"))
                .map(|v| classify_vendor(v.strip_prefix("0x").unwrap_or(&v)))
                .unwrap_or(GpuVendor::Other);
            let driver = fs::read_link(dir.join("driver"))
                .ok()
                .and_then(|target| target.file_name()?.to_str().map(str::to_string));
            Some(PciDisplayDevice {
                address,
                vendor,
                driver,
                dir,
            })
        })
        .collect();
    devices.sort_by(|a, b| a.address.cmp(&b.address));
    devices
}

/// The display devices that no already-known GPU accounts for, by PCI
/// address.
pub fn devices_without_drm_card<'a>(
    known: &[GpuInfo],
    devices: &'a [PciDisplayDevice],
) -> Vec<&'a PciDisplayDevice> {
    let known: HashSet<String> = known
        .iter()
        .filter_map(|g| normalize_pci_address(&g.pci_address))
        .collect();
    devices
        .iter()
        .filter(|d| !known.contains(&d.address))
        .collect()
}

/// Can `nvidia-smi` see this GPU? It lists what the proprietary `nvidia`
/// driver manages. A card reserved for `vfio-pci`, or with no driver, is not
/// among them: counting it would make a one-card system look like a
/// multi-card one and switch off per-process attribution. Every NVIDIA card
/// with a DRM card counts, as before (a `nouveau` one simply gets no answer).
pub fn nvidia_smi_may_see(gpu: &GpuInfo) -> bool {
    gpu.vendor == GpuVendor::Nvidia && (gpu.drm_card || gpu.driver.as_deref() == Some("nvidia"))
}

/// Thin I/O wrapper: enumerates DRM cards, classifies each by vendor from
/// its own `uevent`, then applies vendor-specific enrichment — AMD and
/// Intel via direct sysfs reads (no external tool needed), NVIDIA via one
/// combined `nvidia-smi` call for every NVIDIA GPU at once. Unrecognized
/// vendors get the structural facts (PCI address, driver, description)
/// only. Intel's figures are frequency, throttling and, on discrete cards,
/// temperature/fan/power limit — not utilization or VRAM, which the Intel
/// drivers don't expose in sysfs; this project doesn't guess where it can't
/// verify.
pub fn collect() -> Result<GpuRawData, ModuleError> {
    let cards = list_drm_cards();
    let mut gpus = Vec::new();

    for card in &cards {
        let card_dir = PathBuf::from(format!("/sys/class/drm/{card}"));
        let device_dir = card_dir.join("device");
        let Ok(uevent_text) = fs::read_to_string(device_dir.join("uevent")) else {
            continue;
        };
        let (driver, pci_id, pci_slot_name) = parse_drm_uevent(&uevent_text);
        let (Some(pci_id), Some(pci_address)) = (pci_id, pci_slot_name) else {
            continue;
        };
        let vendor = classify_vendor(&pci_id);
        let description = lookup_pci_description(&pci_address);

        let mut gpu = GpuInfo::new(card.clone(), pci_address, vendor, description, driver, true);

        // Generic PCI feature, applied uniformly regardless of vendor —
        // see enrich_pcie_link_info's doc comment for the known
        // current-vs-max reliability caveat this carries.
        enrich_pcie_link_info(&mut gpu, &device_dir);

        match vendor {
            GpuVendor::Amd => enrich_amd(&mut gpu, &device_dir),
            GpuVendor::Intel => enrich_intel(&mut gpu, &card_dir),
            _ => {}
        }

        gpus.push(gpu);
    }

    // GPUs the kernel exposes no DRM card for: reserved for passthrough
    // (`vfio-pci`), with no driver at all, or compute GPUs whose driver
    // registers no graphics card. Invisible to the loop above, so found on
    // the PCI bus instead. Only the PCIe link can be read for these.
    let pci_devices = scan_pci_display_devices(Path::new("/sys/bus/pci/devices"));
    for device in devices_without_drm_card(&gpus, &pci_devices) {
        let description = lookup_pci_description(&device.address);
        let mut gpu = GpuInfo::new(
            device.address.clone(),
            device.address.clone(),
            device.vendor,
            description,
            device.driver.clone(),
            false,
        );
        enrich_pcie_link_info(&mut gpu, &device.dir);
        gpus.push(gpu);
    }

    let mut nvidia_max_cuda_version = None;

    if gpus.iter().any(nvidia_smi_may_see) {
        // One session for the three nvidia-smi calls: when the driver is
        // wedged the first one times out and the other two are skipped,
        // so the cost is one time limit, not three. `slow()` because the
        // first call after boot can take a few seconds to initialize the
        // driver.
        let mut nvidia = ToolSession::new("nvidia-smi").slow();

        let query = format!("--query-gpu={NVIDIA_QUERY_FIELDS}");
        if let Some(csv) = nvidia.run(&[&query, "--format=csv,noheader,nounits"]) {
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

        // The plain `nvidia-smi` header (no args) is the *only* place the
        // maximum-supported CUDA version is exposed — confirmed not
        // present in `--query-gpu`'s field set.
        if let Some(header) = nvidia.run(&[]) {
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
            .filter(|(_, g)| nvidia_smi_may_see(g))
            .map(|(i, _)| i)
            .collect();
        if nvidia_indices.len() == 1 {
            if let Some(proc_text) = nvidia.run(&[
                "--query-compute-apps=pid,process_name,used_memory",
                "--format=csv,noheader,nounits",
            ]) {
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

    // ----- Intel -----
    //
    // Fake sysfs trees laid out as the kernel's own sources describe them
    // (see `enrich_intel`). They prove the paths, the units and the
    // fall-backs; they cannot prove that a given real card fills them.

    fn fake_card(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("linuxdoctor-gpu-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(root: &Path, relative: &str, content: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn blank_gpu(driver: &str) -> GpuInfo {
        GpuInfo::new(
            "card0".to_string(),
            "0000:00:02.0".to_string(),
            GpuVendor::Intel,
            None,
            Some(driver.to_string()),
            true,
        )
    }

    /// An i915 card with the per-GT layout, every throttle flag at 0 except
    /// the ones listed.
    fn i915_card(name: &str, raised: &[&str]) -> PathBuf {
        let card = fake_card(name);
        put(&card, "gt/gt0/rps_act_freq_mhz", "650\n");
        put(&card, "gt/gt0/rps_RP0_freq_mhz", "1100\n");
        put(&card, "gt/gt0/rps_max_freq_mhz", "900\n");
        let any = !raised.is_empty();
        put(
            &card,
            "gt/gt0/throttle_reason_status",
            if any { "1\n" } else { "0\n" },
        );
        for reason in INTEL_THROTTLE_REASONS {
            let value = if raised.contains(&reason) {
                "1\n"
            } else {
                "0\n"
            };
            put(&card, &format!("gt/gt0/throttle_reason_{reason}"), value);
        }
        card
    }

    #[test]
    fn a_sysfs_flag_is_one_or_zero_and_nothing_else() {
        assert_eq!(parse_flag("1\n"), Some(true));
        assert_eq!(parse_flag("0\n"), Some(false));
        assert_eq!(parse_flag(" 1 "), Some(true));
        for odd in ["", "2", "yes", "true", "-1", "10"] {
            assert_eq!(parse_flag(odd), None, "{odd:?}");
        }
    }

    #[test]
    fn xe_throttle_reasons_are_read_from_the_space_separated_list() {
        // The kernel writes a space after every name, trailing one included.
        assert_eq!(
            parse_throttle_reasons("pl1 thermal \n"),
            vec!["pl1".to_string(), "thermal".to_string()]
        );
        assert!(parse_throttle_reasons("none\n").is_empty());
        assert!(parse_throttle_reasons("").is_empty());
        assert_eq!(
            parse_throttle_reasons("PL2 pl2 pl2\n"),
            vec!["pl2".to_string()],
            "lowercased, and each name once"
        );
    }

    #[test]
    fn throttle_reasons_that_are_not_plain_names_are_dropped_not_shown() {
        let long = "a".repeat(MAX_REASON_NAME_LEN + 1);
        let text = format!("pl1 \u{1b}[31mred {long} a-b é thermal");
        assert_eq!(
            parse_throttle_reasons(&text),
            vec!["pl1".to_string(), "thermal".to_string()]
        );
        let many: String = (0..30).map(|i| format!("r{i} ")).collect();
        assert_eq!(parse_throttle_reasons(&many).len(), MAX_REASONS);
    }

    #[test]
    fn only_temperature_reasons_count_as_thermal() {
        for thermal in [
            "thermal",
            "ratl",
            "vr_thermalert",
            "vr_thermal",
            "soc_thermal",
            "mem_thermal",
            "soc_avg_thermal",
        ] {
            assert!(is_thermal_throttle_reason(thermal), "{thermal}");
        }
        for other in [
            "pl1", "pl2", "pl4", "prochot", "vr_tdc", "iccmax", "pwrbrk", "",
        ] {
            assert!(!is_thermal_throttle_reason(other), "{other:?}");
        }
    }

    #[test]
    fn a_reason_seen_proves_throttling_even_if_the_status_said_no() {
        let one = vec!["pl1".to_string()];
        assert_eq!(
            settle_throttle(Some(true), one.clone()),
            (Some(true), one.clone())
        );
        assert_eq!(
            settle_throttle(Some(false), one.clone()),
            (Some(true), one.clone())
        );
        assert_eq!(settle_throttle(None, one.clone()), (Some(true), one));
        assert_eq!(settle_throttle(Some(true), vec![]), (Some(true), vec![]));
        assert_eq!(settle_throttle(Some(false), vec![]), (Some(false), vec![]));
        assert_eq!(settle_throttle(None, vec![]), (None, vec![]));
    }

    #[test]
    fn i915_frequencies_and_throttling_come_from_the_per_gt_directory() {
        let card = i915_card("i915-pergt", &["pl1", "pl2"]);
        let mut gpu = blank_gpu("i915");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.clock_core_mhz, Some(650));
        assert_eq!(gpu.idle, Some(false));
        assert_eq!(gpu.clock_hw_max_mhz, Some(1100));
        assert_eq!(gpu.clock_limit_mhz, Some(900));
        assert_eq!(gpu.throttled, Some(true));
        assert_eq!(gpu.throttle_reasons, ["pl1", "pl2"]);
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn i915_with_nothing_raised_is_not_throttled() {
        let card = i915_card("i915-calm", &[]);
        let mut gpu = blank_gpu("i915");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.throttled, Some(false));
        assert!(gpu.throttle_reasons.is_empty());
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn a_zero_actual_frequency_means_asleep_not_a_clock_of_zero() {
        let card = i915_card("i915-asleep", &[]);
        put(&card, "gt/gt0/rps_act_freq_mhz", "0\n");
        let mut gpu = blank_gpu("i915");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.idle, Some(true));
        assert_eq!(gpu.clock_core_mhz, None);
        assert_eq!(gpu.clock_hw_max_mhz, Some(1100), "the range is still known");
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn i915_falls_back_to_the_flat_files_of_older_kernels() {
        let card = fake_card("i915-legacy");
        put(&card, "gt_act_freq_mhz", "300\n");
        put(&card, "gt_RP0_freq_mhz", "1050\n");
        put(&card, "gt_max_freq_mhz", "1050\n");
        let mut gpu = blank_gpu("i915");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.clock_core_mhz, Some(300));
        assert_eq!(gpu.clock_hw_max_mhz, Some(1050));
        assert_eq!(gpu.clock_limit_mhz, Some(1050));
        assert_eq!(gpu.throttled, None, "those kernels have no throttle files");
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn xe_reads_the_freq0_directory_and_never_the_current_frequency_file() {
        let card = fake_card("xe-freq");
        let freq = "device/tile0/gt0/freq0";
        put(&card, &format!("{freq}/act_freq"), "1200\n");
        put(&card, &format!("{freq}/rp0_freq"), "2400\n");
        put(&card, &format!("{freq}/max_freq"), "2000\n");
        // Reading this one wakes the GPU up; its value must not be used.
        put(&card, &format!("{freq}/cur_freq"), "9999\n");
        put(&card, &format!("{freq}/throttle/status"), "1\n");
        put(&card, &format!("{freq}/throttle/reasons"), "pl1 thermal \n");
        let mut gpu = blank_gpu("xe");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.clock_core_mhz, Some(1200));
        assert_eq!(gpu.clock_hw_max_mhz, Some(2400));
        assert_eq!(gpu.clock_limit_mhz, Some(2000));
        assert_eq!(gpu.throttled, Some(true));
        assert_eq!(gpu.throttle_reasons, ["pl1", "thermal"]);
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn xe_asleep_and_not_throttled() {
        let card = fake_card("xe-asleep");
        let freq = "device/tile0/gt0/freq0";
        put(&card, &format!("{freq}/act_freq"), "0\n");
        put(&card, &format!("{freq}/throttle/status"), "0\n");
        put(&card, &format!("{freq}/throttle/reasons"), "none\n");
        let mut gpu = blank_gpu("xe");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.idle, Some(true));
        assert_eq!(gpu.clock_core_mhz, None);
        assert_eq!(gpu.throttled, Some(false));
        assert!(gpu.throttle_reasons.is_empty());
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn i915_discrete_card_gets_temperature_fan_and_power_limit_from_its_own_hwmon() {
        let card = i915_card("i915-hwmon", &[]);
        // Another chip on the same device, hotter, that must be ignored.
        put(&card, "device/hwmon/hwmon2/name", "nvme\n");
        put(&card, "device/hwmon/hwmon2/temp1_input", "99000\n");
        put(&card, "device/hwmon/hwmon3/name", "i915\n");
        put(&card, "device/hwmon/hwmon3/temp1_input", "52500\n");
        put(&card, "device/hwmon/hwmon3/fan1_input", "1800\n");
        put(&card, "device/hwmon/hwmon3/power1_max", "190000000\n");
        let mut gpu = blank_gpu("i915");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.temperature_c, Some(52.5));
        assert_eq!(gpu.temperature_crit_c, None, "i915 has no critical value");
        assert_eq!(gpu.fan_rpm, Some(1800));
        assert_eq!(gpu.power_limit_w, Some(190.0));
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn xe_uses_the_second_temperature_sensor_and_its_critical_value() {
        let card = fake_card("xe-hwmon");
        put(&card, "device/hwmon/hwmon4/name", "xe\n");
        put(&card, "device/hwmon/hwmon4/temp1_input", "10000\n");
        put(&card, "device/hwmon/hwmon4/temp2_input", "61000\n");
        put(&card, "device/hwmon/hwmon4/temp2_crit", "100000\n");
        put(&card, "device/hwmon/hwmon4/fan1_input", "2100\n");
        put(&card, "device/hwmon/hwmon4/power1_max", "225000000\n");
        let mut gpu = blank_gpu("xe");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.temperature_c, Some(61.0));
        assert_eq!(gpu.temperature_crit_c, Some(100.0));
        assert_eq!(gpu.fan_rpm, Some(2100));
        assert_eq!(gpu.power_limit_w, Some(225.0));
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn a_power_limit_of_zero_means_disabled_and_is_not_reported_as_a_limit() {
        let card = i915_card("i915-nolimit", &[]);
        put(&card, "device/hwmon/hwmon3/name", "i915\n");
        put(&card, "device/hwmon/hwmon3/power1_max", "0\n");
        let mut gpu = blank_gpu("i915");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.power_limit_w, None);
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn an_integrated_gpu_without_hwmon_simply_has_no_temperature() {
        let card = i915_card("i915-igpu", &[]);
        let mut gpu = blank_gpu("i915");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.temperature_c, None);
        assert_eq!(gpu.fan_rpm, None);
        assert_eq!(gpu.power_limit_w, None);
        assert_eq!(gpu.clock_core_mhz, Some(650), "the rest is still read");
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn a_hwmon_chip_that_is_not_intels_is_not_read() {
        let card = fake_card("other-hwmon");
        put(&card, "device/hwmon/hwmon0/name", "coretemp\n");
        put(&card, "device/hwmon/hwmon0/temp1_input", "70000\n");
        let mut gpu = blank_gpu("i915");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.temperature_c, None);
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn nothing_is_read_for_an_intel_device_bound_to_another_driver() {
        // Passed through to a VM, say: the files below may exist, but they
        // are not the driver's to vouch for.
        let card = i915_card("vfio", &["thermal"]);
        put(&card, "device/hwmon/hwmon3/name", "i915\n");
        put(&card, "device/hwmon/hwmon3/temp1_input", "52500\n");
        let mut passthrough = blank_gpu("vfio-pci");
        enrich_intel(&mut passthrough, &card);
        assert_eq!(passthrough, blank_gpu("vfio-pci"));
        let mut gpu = blank_gpu("i915");
        gpu.driver = None;
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.clock_core_mhz, None);
        let _ = fs::remove_dir_all(card);
    }

    #[test]
    fn an_empty_card_directory_leaves_every_intel_field_empty() {
        for driver in ["i915", "xe"] {
            let card = fake_card(&format!("empty-{driver}"));
            let mut gpu = blank_gpu(driver);
            enrich_intel(&mut gpu, &card);
            assert_eq!(gpu, blank_gpu(driver));
            let _ = fs::remove_dir_all(card);
        }
    }

    #[test]
    fn garbage_in_a_sysfs_file_is_ignored_not_guessed_at() {
        let card = i915_card("i915-garbage", &[]);
        put(&card, "gt/gt0/rps_act_freq_mhz", "fast\n");
        put(&card, "gt/gt0/rps_RP0_freq_mhz", "0\n");
        put(&card, "gt/gt0/rps_max_freq_mhz", "-5\n");
        let mut gpu = blank_gpu("i915");
        enrich_intel(&mut gpu, &card);
        assert_eq!(gpu.clock_core_mhz, None);
        assert_eq!(gpu.idle, None, "unreadable is not the same as asleep");
        assert_eq!(gpu.clock_hw_max_mhz, None, "a zero maximum is no maximum");
        assert_eq!(gpu.clock_limit_mhz, None);
        let _ = fs::remove_dir_all(card);
    }

    // ----- GPUs found on the PCI bus instead of under /sys/class/drm -----

    /// One entry of a fake `/sys/bus/pci/devices`.
    fn pci_device(root: &Path, address: &str, class: &str, vendor: &str, driver: Option<&str>) {
        put(root, &format!("{address}/class"), class);
        put(root, &format!("{address}/vendor"), vendor);
        if let Some(driver) = driver {
            let target = root.join("drivers").join(driver);
            fs::create_dir_all(&target).unwrap();
            std::os::unix::fs::symlink(&target, root.join(address).join("driver")).unwrap();
        }
    }

    #[test]
    fn a_pci_class_is_the_kernels_0x_and_six_hex_digits() {
        assert_eq!(parse_pci_class("0x030000\n"), Some(0x030000));
        assert_eq!(parse_pci_class("0x038000"), Some(0x038000));
        for odd in ["030000", "0x", "", "0xzz", "class"] {
            assert_eq!(parse_pci_class(odd), None, "{odd:?}");
        }
    }

    #[test]
    fn only_display_controllers_count_as_gpus() {
        // VGA, 3D controller (NVIDIA compute cards), other display controller.
        for class in [0x030000, 0x030200, 0x038000] {
            assert!(is_display_class(class), "{class:#x}");
        }
        // The card's audio function, a bridge, USB, a NIC, nothing.
        for class in [0x040300, 0x060400, 0x0c0330, 0x020000, 0x000000] {
            assert!(!is_display_class(class), "{class:#x}");
        }
    }

    #[test]
    fn the_pci_scan_finds_display_devices_with_their_vendor_and_driver() {
        let root = fake_card("pci-scan");
        pci_device(
            &root,
            "0000:04:00.0",
            "0x030000\n",
            "0x10de\n",
            Some("vfio-pci"),
        );
        pci_device(
            &root,
            "0000:02:00.0",
            "0x030000\n",
            "0x10DE\n",
            Some("nvidia"),
        );
        pci_device(&root, "0000:0b:00.0", "0x030000\n", "0x1a03\n", None);
        pci_device(
            &root,
            "0000:3b:00.0",
            "0x030200\n",
            "0x10de\n",
            Some("nvidia"),
        );
        // Not GPUs: the card's audio function, a bridge.
        pci_device(
            &root,
            "0000:04:00.1",
            "0x040300\n",
            "0x10de\n",
            Some("snd_hda_intel"),
        );
        pci_device(
            &root,
            "0000:00:01.0",
            "0x060400\n",
            "0x8086\n",
            Some("pcieport"),
        );

        let found = scan_pci_display_devices(&root);
        let summary: Vec<(&str, GpuVendor, Option<&str>)> = found
            .iter()
            .map(|d| (d.address.as_str(), d.vendor, d.driver.as_deref()))
            .collect();
        assert_eq!(
            summary,
            [
                ("0000:02:00.0", GpuVendor::Nvidia, Some("nvidia")),
                ("0000:04:00.0", GpuVendor::Nvidia, Some("vfio-pci")),
                ("0000:0b:00.0", GpuVendor::Other, None),
                ("0000:3b:00.0", GpuVendor::Nvidia, Some("nvidia")),
            ],
            "sorted by address; the `drivers` directory is not a device"
        );
        assert_eq!(found[1].dir, root.join("0000:04:00.0"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn an_sriov_virtual_function_is_not_counted_as_a_gpu_of_its_own() {
        let root = fake_card("pci-vf");
        pci_device(
            &root,
            "0000:05:00.0",
            "0x030200\n",
            "0x10de\n",
            Some("nvidia"),
        );
        pci_device(
            &root,
            "0000:05:00.4",
            "0x030200\n",
            "0x10de\n",
            Some("vfio-pci"),
        );
        std::os::unix::fs::symlink(root.join("0000:05:00.0"), root.join("0000:05:00.4/physfn"))
            .unwrap();
        let found = scan_pci_display_devices(&root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, "0000:05:00.0");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unreadable_entries_are_skipped_and_an_unreadable_vendor_is_other() {
        let root = fake_card("pci-odd");
        put(&root, "0000:06:00.0/class", "garbage\n");
        fs::create_dir_all(root.join("0000:07:00.0")).unwrap(); // no class file
        put(&root, "0000:08:00.0/class", "0x030000\n"); // no vendor file
        let found = scan_pci_display_devices(&root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, "0000:08:00.0");
        assert_eq!(found[0].vendor, GpuVendor::Other);
        assert_eq!(found[0].driver, None);
        let _ = fs::remove_dir_all(root);
        assert!(
            scan_pci_display_devices(&std::env::temp_dir().join("no-such-pci-root")).is_empty()
        );
    }

    #[test]
    fn a_device_already_known_through_its_drm_card_is_not_listed_twice() {
        let known = [GpuInfo::new(
            "card0".to_string(),
            "0000:0B:00.0".to_string(), // upper case, as a driver might print it
            GpuVendor::Nvidia,
            None,
            Some("nvidia".to_string()),
            true,
        )];
        let device = |address: &str| PciDisplayDevice {
            address: address.to_string(),
            vendor: GpuVendor::Nvidia,
            driver: None,
            dir: PathBuf::from("/nonexistent"),
        };
        let devices = [device("0000:0b:00.0"), device("0000:04:00.0")];
        let left: Vec<&str> = devices_without_drm_card(&known, &devices)
            .iter()
            .map(|d| d.address.as_str())
            .collect();
        assert_eq!(left, ["0000:04:00.0"]);
    }

    #[test]
    fn nvidia_smi_is_only_expected_to_see_cards_the_nvidia_driver_manages() {
        let gpu = |vendor, driver: Option<&str>, drm_card| {
            GpuInfo::new(
                "x".to_string(),
                "0000:01:00.0".to_string(),
                vendor,
                None,
                driver.map(str::to_string),
                drm_card,
            )
        };
        assert!(nvidia_smi_may_see(&gpu(
            GpuVendor::Nvidia,
            Some("nvidia"),
            true
        )));
        assert!(nvidia_smi_may_see(&gpu(
            GpuVendor::Nvidia,
            Some("nouveau"),
            true
        )));
        // A compute GPU with no graphics card is still the driver's.
        assert!(nvidia_smi_may_see(&gpu(
            GpuVendor::Nvidia,
            Some("nvidia"),
            false
        )));
        // Reserved for a VM, or with nothing bound: not visible to nvidia-smi.
        assert!(!nvidia_smi_may_see(&gpu(
            GpuVendor::Nvidia,
            Some("vfio-pci"),
            false
        )));
        assert!(!nvidia_smi_may_see(&gpu(GpuVendor::Nvidia, None, false)));
        assert!(!nvidia_smi_may_see(&gpu(
            GpuVendor::Amd,
            Some("amdgpu"),
            true
        )));
    }
}
