// SPDX-License-Identifier: GPL-3.0-only

use std::fs;
use std::process::Command;

use crate::core::error::ModuleError;

#[derive(Debug, Clone, PartialEq)]
pub struct VirtualizationRawData {
    /// Whether `systemd-detect-virt` itself is installed and runnable.
    pub tool_available: bool,
    /// `systemd-detect-virt --vm` — hardware/hypervisor-level
    /// virtualization only. "none" (not absence) means "checked, bare
    /// metal at this layer".
    pub vm_type: Option<String>,
    /// `systemd-detect-virt --container` — same-kernel (container-level)
    /// virtualization only.
    pub container_type: Option<String>,
    /// Fallback fact when the tool isn't installed: the CPUID
    /// "hypervisor" flag from `/proc/cpuinfo`. Weaker than
    /// systemd-detect-virt (confirms *some* hardware virtualization is
    /// present, but not which one, and says nothing about containers).
    pub cpuinfo_hypervisor_flag: bool,
}

/// Thin I/O wrapper: `systemd-detect-virt` doesn't need systemd as PID 1
/// (unlike `systemctl`/`timedatectl`) — it probes DMI/CPUID/environment
/// markers directly — so this module has no availability gate the way
/// Systemd/NTP do.
pub fn collect() -> Result<VirtualizationRawData, ModuleError> {
    let tool_available = Command::new("systemd-detect-virt")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let (vm_type, container_type) = if tool_available {
        (run_detect_virt(&["--vm"]), run_detect_virt(&["--container"]))
    } else {
        (None, None)
    };

    let cpuinfo_text = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpuinfo_hypervisor_flag = detect_hypervisor_flag(&cpuinfo_text);

    Ok(VirtualizationRawData {
        tool_available,
        vm_type,
        container_type,
        cpuinfo_hypervisor_flag,
    })
}

/// `systemd-detect-virt` exits *non-zero* specifically when it detects
/// "none" (per its own man page: "0 if a virtualization technology is
/// detected, non-zero otherwise") — so stdout is read regardless of exit
/// status, the same permissive pattern used for `df`. Treating a non-zero
/// exit as a collection failure here would misreport every bare-metal
/// machine as an error.
fn run_detect_virt(args: &[&str]) -> Option<String> {
    let output = Command::new("systemd-detect-virt").args(args).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Parse the CPUID "hypervisor" flag out of `/proc/cpuinfo`'s `flags:`
/// line. Pure function, tested against fixture text.
pub fn detect_hypervisor_flag(cpuinfo_text: &str) -> bool {
    cpuinfo_text
        .lines()
        .find(|l| l.trim_start().starts_with("flags"))
        .map(|l| l.split_whitespace().any(|f| f == "hypervisor"))
        .unwrap_or(false)
}

/// Translate systemd-detect-virt's short IDs into names people recognize.
/// Not exhaustive (the tool defines 25+ IDs) — falls back to the raw ID
/// for anything not in this small, curated list of the common ones.
pub fn friendly_name(id: &str) -> String {
    match id {
        "none" => "none",
        "kvm" => "KVM",
        "qemu" => "QEMU",
        "vmware" => "VMware",
        "oracle" => "VirtualBox (Oracle)",
        "microsoft" => "Hyper-V (Microsoft)",
        "xen" => "Xen",
        "amazon" => "AWS Nitro",
        "google" => "Google Compute Engine",
        "bochs" => "Bochs",
        "parallels" => "Parallels",
        "uml" => "User-Mode Linux",
        "docker" => "Docker",
        "podman" => "Podman",
        "lxc" => "LXC",
        "lxc-libvirt" => "LXC (libvirt-managed)",
        "openvz" => "OpenVZ",
        "systemd-nspawn" => "systemd-nspawn",
        "wsl" => "Windows Subsystem for Linux",
        other => return other.to_string(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_hypervisor_flag_present() {
        let text = "processor\t: 0\nflags\t\t: fpu vme de pse hypervisor tsc msr\n";
        assert!(detect_hypervisor_flag(text));
    }

    #[test]
    fn hypervisor_flag_absent_on_bare_metal_fixture() {
        let text = "processor\t: 0\nflags\t\t: fpu vme de pse tsc msr\n";
        assert!(!detect_hypervisor_flag(text));
    }

    #[test]
    fn missing_flags_line_is_false_not_a_panic() {
        assert!(!detect_hypervisor_flag("processor\t: 0\n"));
    }

    #[test]
    fn friendly_name_maps_known_ids() {
        assert_eq!(friendly_name("kvm"), "KVM");
        assert_eq!(friendly_name("docker"), "Docker");
        assert_eq!(friendly_name("none"), "none");
    }

    #[test]
    fn friendly_name_falls_back_to_raw_id_for_unknown() {
        assert_eq!(friendly_name("acrn"), "acrn");
    }
}
