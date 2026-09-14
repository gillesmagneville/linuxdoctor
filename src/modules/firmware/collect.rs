// SPDX-License-Identifier: GPL-3.0-only

use std::fs;
use std::path::Path;

use crate::core::command::command;
use crate::core::error::ModuleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    Uefi,
    Legacy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FirmwareRawData {
    /// From `/sys/class/dmi/id/*` — plain sysfs reads, no root needed for
    /// any of these (confirmed real permissions during research: world-
    /// readable, unlike `board_serial`/`chassis_serial` which are
    /// root-only and deliberately not read here — they're identifying
    /// serial numbers with no diagnostic value for this project).
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    pub bios_date: Option<String>,
    /// The SMBIOS "BIOS Revision" field (e.g. "5.13") — distinct from
    /// `bios_version`, which is the vendor's own free-form version
    /// string (e.g. "GL702ZC.305"). Vendors don't always keep the two
    /// in step with each other.
    pub bios_release: Option<String>,
    pub board_vendor: Option<String>,
    pub board_name: Option<String>,
    pub boot_mode: BootMode,
    /// `None` when `mokutil` isn't installed. Deliberately not falling
    /// back to parsing the raw `/sys/firmware/efi/efivars/SecureBoot-*`
    /// EFI variable's bytes: independent sources found during research
    /// disagreed on the exact byte offset to check, and a security-
    /// relevant fact is exactly the wrong place to guess.
    pub secure_boot_enabled: Option<bool>,
    pub tpm_present: bool,
    /// Whether `/proc/cpuinfo` reports the `vmx` (Intel VT-x) or `svm`
    /// (AMD-V) flag. Only x86-meaningful — analyze.rs gates whether to
    /// report on this by `Context::architecture`, since `collect()`
    /// stays architecture-agnostic per this project's own convention
    /// (see ARCHITECTURE.md "Collectors").
    pub virt_flag_present: bool,
    /// Whether the `kvm_intel`/`kvm_amd` kernel module is currently
    /// loaded (`/proc/cmdline` — same data `lsmod` reads, without the
    /// subprocess call).
    pub kvm_module_loaded: bool,
    /// Whether the *current* `dmesg` ring buffer contains "disabled by
    /// bios" — the confirmed real message KVM logs when the CPU flag is
    /// present but the BIOS has blocked it. A buffer that's rotated past
    /// boot-time messages makes this `false` without meaning "confirmed
    /// not disabled" — analyze.rs's wording reflects that.
    pub dmesg_shows_bios_disabled: bool,
    /// Whether the kernel command line asked for IOMMU via any of the
    /// confirmed real parameter spellings (`iommu=`, `intel_iommu=`,
    /// `amd_iommu=`).
    pub iommu_kernel_param_requested: bool,
    /// Whether `/sys/class/iommu/` actually has any entries — the
    /// kernel's own signal that IOMMU is live, independent of whether it
    /// was explicitly requested on the command line (some platforms
    /// default it on).
    pub iommu_active: bool,
}

fn read_dmi(name: &str) -> Option<String> {
    fs::read_to_string(format!("/sys/class/dmi/id/{name}"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn detect_boot_mode() -> BootMode {
    if Path::new("/sys/firmware/efi").exists() {
        BootMode::Uefi
    } else {
        BootMode::Legacy
    }
}

/// `mokutil --sb-state` gives a clean "SecureBoot enabled"/"SecureBoot
/// disabled" line — confirmed real output format via several
/// independent sources during research.
fn detect_secure_boot() -> Option<bool> {
    let output = command("mokutil").arg("--sb-state").output().ok()?;
    parse_secure_boot_state(&String::from_utf8_lossy(&output.stdout))
}

pub fn parse_secure_boot_state(text: &str) -> Option<bool> {
    let lower = text.to_lowercase();
    if lower.contains("secureboot enabled") {
        Some(true)
    } else if lower.contains("secureboot disabled") {
        Some(false)
    } else {
        None
    }
}

fn detect_tpm_present() -> bool {
    fs::read_dir("/sys/class/tpm")
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

/// Whether the kernel command line asked for IOMMU, under any of the
/// confirmed real spellings. `param.split_once('=')` also correctly
/// handles a bare flag with no value (falls back to the whole token as
/// the key), though none of these three normally appear that way.
pub fn parse_iommu_requested(cmdline: &str) -> bool {
    cmdline.split_whitespace().any(|param| {
        let key = param.split_once('=').map(|(k, _)| k).unwrap_or(param);
        matches!(key, "iommu" | "intel_iommu" | "amd_iommu")
    })
}

fn detect_iommu_active() -> bool {
    fs::read_dir("/sys/class/iommu")
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

/// Parse `/proc/cpuinfo`'s "flags" line for `vmx`/`svm`. Only the first
/// logical CPU's flags line is checked — every core on one physical
/// machine shares the same feature set on every system this project
/// targets, so checking the rest would be redundant work for no
/// additional information.
pub fn parse_virt_flag_present(cpuinfo: &str) -> bool {
    cpuinfo
        .lines()
        .find(|l| l.starts_with("flags"))
        .map(|l| l.split_whitespace().any(|f| f == "vmx" || f == "svm"))
        .unwrap_or(false)
}

/// `/proc/modules` is exactly what `lsmod` itself reads — checking it
/// directly avoids a subprocess call for something this simple. Format:
/// one module per line, name first, whitespace-separated.
pub fn parse_kvm_module_loaded(modules_text: &str) -> bool {
    modules_text
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .any(|name| name == "kvm_intel" || name == "kvm_amd")
}

fn dmesg_shows_bios_disabled() -> bool {
    let Ok(output) = command("dmesg").output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout)
        .to_lowercase()
        .contains("disabled by bios")
}

/// Thin I/O wrapper: every fact here is architecture-agnostic to
/// collect (even `virt_flag_present` is just "did this string appear in
/// this file" — whether it's *meaningful* on this architecture is an
/// interpretation decision, left to `analyze()` per this project's own
/// collect/analyze split).
pub fn collect() -> Result<FirmwareRawData, ModuleError> {
    let cpuinfo_text = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let modules_text = fs::read_to_string("/proc/modules").unwrap_or_default();
    let cmdline_text = fs::read_to_string("/proc/cmdline").unwrap_or_default();

    Ok(FirmwareRawData {
        bios_vendor: read_dmi("bios_vendor"),
        bios_version: read_dmi("bios_version"),
        bios_date: read_dmi("bios_date"),
        bios_release: read_dmi("bios_release"),
        board_vendor: read_dmi("board_vendor"),
        board_name: read_dmi("board_name"),
        boot_mode: detect_boot_mode(),
        secure_boot_enabled: detect_secure_boot(),
        tpm_present: detect_tpm_present(),
        virt_flag_present: parse_virt_flag_present(&cpuinfo_text),
        kvm_module_loaded: parse_kvm_module_loaded(&modules_text),
        dmesg_shows_bios_disabled: dmesg_shows_bios_disabled(),
        iommu_kernel_param_requested: parse_iommu_requested(&cmdline_text),
        iommu_active: detect_iommu_active(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_secure_boot_enabled() {
        assert_eq!(parse_secure_boot_state("SecureBoot enabled\n"), Some(true));
    }

    #[test]
    fn parses_secure_boot_disabled() {
        assert_eq!(parse_secure_boot_state("SecureBoot disabled\n"), Some(false));
    }

    #[test]
    fn secure_boot_none_when_unsupported_or_unparseable() {
        // Real confirmed alternative mokutil output for non-UEFI systems.
        assert_eq!(
            parse_secure_boot_state("This system doesn't support Secure Boot\n"),
            None
        );
        assert_eq!(parse_secure_boot_state(""), None);
    }

    #[test]
    fn detects_iommu_param_variants() {
        assert!(parse_iommu_requested("quiet intel_iommu=on splash"));
        assert!(parse_iommu_requested("amd_iommu=on"));
        assert!(parse_iommu_requested("iommu=pt"));
        assert!(!parse_iommu_requested("quiet splash root=/dev/sda1"));
    }

    #[test]
    fn iommu_param_does_not_false_positive_on_similar_names() {
        // e.g. a hypothetical "my_iommu_debug=1" must not match --
        // matching must be on the exact parameter key, not a substring.
        assert!(!parse_iommu_requested("my_iommu_debug=1"));
    }

    const FIXTURE_CPUINFO_VMX: &str = "\
processor\t: 0
flags\t\t: fpu vme de pse tsc msr vmx sse sse2
";

    #[test]
    fn detects_vmx_flag() {
        assert!(parse_virt_flag_present(FIXTURE_CPUINFO_VMX));
    }

    const FIXTURE_CPUINFO_SVM: &str = "\
processor\t: 0
flags\t\t: fpu vme de pse tsc msr svm sse sse2
";

    #[test]
    fn detects_svm_flag() {
        assert!(parse_virt_flag_present(FIXTURE_CPUINFO_SVM));
    }

    #[test]
    fn no_virt_flag_when_absent() {
        let text = "processor\t: 0\nflags\t\t: fpu vme de pse tsc msr sse sse2\n";
        assert!(!parse_virt_flag_present(text));
    }

    #[test]
    fn only_checks_first_flags_line() {
        // Two CPUs; only the first is consulted (see doc comment on why
        // checking more would be redundant on real hardware).
        let text = "processor\t: 0\nflags\t\t: fpu vmx\nprocessor\t: 1\nflags\t\t: fpu\n";
        assert!(parse_virt_flag_present(text));
    }

    const FIXTURE_PROC_MODULES_KVM: &str = "\
kvm_intel 372736 0 - Live 0x0000000000000000
kvm 1077248 1 kvm_intel, Live 0x0000000000000000
irqbypass 16384 1 kvm, Live 0x0000000000000000
";

    #[test]
    fn detects_loaded_kvm_intel_module() {
        assert!(parse_kvm_module_loaded(FIXTURE_PROC_MODULES_KVM));
    }

    #[test]
    fn no_kvm_module_when_absent() {
        let text = "ext4 819200 1 - Live 0x0000000000000000\n";
        assert!(!parse_kvm_module_loaded(text));
    }

    #[test]
    fn kvm_module_name_match_is_exact_not_substring() {
        // A module named e.g. "kvm_intel_extra" must not false-match.
        let text = "kvm_intel_extra 4096 0 - Live 0x0000000000000000\n";
        assert!(!parse_kvm_module_loaded(text));
    }
}
