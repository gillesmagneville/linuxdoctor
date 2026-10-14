// SPDX-License-Identifier: GPL-3.0-only

use std::fs;

use crate::core::command::command;
use crate::core::error::ModuleError;
use crate::models::Severity;

#[derive(Debug, Clone, PartialEq)]
pub struct KernelRawData {
    pub tainted_raw: u64,
    /// `None` means the check couldn't run at all (dmesg unavailable or
    /// permission denied — see `dmesg_error` for why), not "zero found".
    pub oom_kill_count: Option<usize>,
    pub dmesg_error: Option<String>,
    pub build_info: KernelBuildInfo,
    pub reboot_required: RebootRequiredInfo,
    pub aslr_mode: Option<u8>,
    pub notable_cmdline_flags: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KernelBuildInfo {
    pub build_user_host: Option<String>,
    pub compiler: Option<String>,
    pub build_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RebootRequiredInfo {
    pub marker_present: bool,
    pub packages: Vec<String>,
}

/// One row of the kernel taint bitfield. Source: the kernel's own
/// documentation (Documentation/admin-guide/tainted-kernels.rst /
/// https://docs.kernel.org/admin-guide/tainted-kernels.html) — every bit,
/// short code, and description below is transcribed from that table, not
/// guessed. Severity judgments (which of these actually warrant
/// attention vs. are routine/deliberate) are this project's own.
pub struct TaintBit {
    pub bit: u32,
    pub code: &'static str,
    pub severity: Severity,
    pub description: &'static str,
}

pub const TAINT_BITS: &[TaintBit] = &[
    TaintBit {
        bit: 0,
        code: "P",
        severity: Severity::Info,
        description: "a proprietary module was loaded",
    },
    TaintBit {
        bit: 1,
        code: "F",
        severity: Severity::Warning,
        description: "a module was force-loaded (insmod -f)",
    },
    TaintBit {
        bit: 2,
        code: "S",
        severity: Severity::Warning,
        description: "the kernel is running on an out-of-specification hardware configuration",
    },
    TaintBit {
        bit: 3,
        code: "R",
        severity: Severity::Warning,
        description: "a module was force-unloaded (rmmod -f)",
    },
    TaintBit {
        bit: 4,
        code: "M",
        severity: Severity::Error,
        description:
            "a processor reported a Machine Check Exception (MCE) — possible hardware fault",
    },
    TaintBit {
        bit: 5,
        code: "B",
        severity: Severity::Error,
        description:
            "a bad page reference or unexpected page flags were found — hardware or kernel bug",
    },
    TaintBit {
        bit: 6,
        code: "U",
        severity: Severity::Info,
        description: "userspace explicitly requested the tainted flag be set",
    },
    TaintBit {
        bit: 7,
        code: "D",
        severity: Severity::Error,
        description: "the kernel died recently (an OOPS or BUG occurred)",
    },
    TaintBit {
        bit: 8,
        code: "A",
        severity: Severity::Info,
        description: "an ACPI table was overridden by the administrator",
    },
    TaintBit {
        bit: 9,
        code: "W",
        severity: Severity::Warning,
        description: "the kernel issued a warning (WARN)",
    },
    TaintBit {
        bit: 10,
        code: "C",
        severity: Severity::Info,
        description: "a staging (not yet fully mainlined) driver was loaded",
    },
    TaintBit {
        bit: 11,
        code: "I",
        severity: Severity::Info,
        description: "the kernel worked around a bug in the platform firmware (BIOS/UEFI)",
    },
    TaintBit {
        bit: 12,
        code: "O",
        severity: Severity::Info,
        description: "an externally-built (\"out-of-tree\") module was loaded",
    },
    TaintBit {
        bit: 13,
        code: "E",
        severity: Severity::Info,
        description: "an unsigned module was loaded",
    },
    TaintBit {
        bit: 14,
        code: "L",
        severity: Severity::Error,
        description: "a soft lockup occurred (a CPU was stuck for an extended period)",
    },
    TaintBit {
        bit: 15,
        code: "K",
        severity: Severity::Info,
        description: "the kernel has been live-patched",
    },
    TaintBit {
        bit: 16,
        code: "X",
        severity: Severity::Info,
        description: "an auxiliary, distribution-defined taint flag is set",
    },
    TaintBit {
        bit: 17,
        code: "T",
        severity: Severity::Info,
        description: "the kernel was built with the struct randomization plugin",
    },
    TaintBit {
        bit: 18,
        code: "N",
        severity: Severity::Info,
        description: "an in-kernel test (e.g. KUnit) has been run",
    },
    TaintBit {
        bit: 19,
        code: "J",
        severity: Severity::Warning,
        description: "userspace used a mutating debug operation via /dev/fwctl",
    },
];

/// Thin I/O wrapper: reads /proc/sys/kernel/tainted, and shells out to
/// `dmesg` for OOM killer history (best-effort — see the OOM-kill finding
/// for why a permission failure there isn't treated as a module error).
pub fn collect() -> Result<KernelRawData, ModuleError> {
    let tainted_text =
        fs::read_to_string("/proc/sys/kernel/tainted").map_err(|source| ModuleError::Io {
            path: "/proc/sys/kernel/tainted".to_string(),
            source,
        })?;
    let tainted_raw = parse_tainted(&tainted_text)?;

    let (oom_kill_count, dmesg_error) = match command("dmesg").output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            (Some(count_oom_kills(&text)), None)
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let reason = if stderr.is_empty() {
                "dmesg exited with an error".to_string()
            } else {
                stderr
            };
            (None, Some(reason))
        }
        Err(e) => (None, Some(e.to_string())),
    };

    let build_info = fs::read_to_string("/proc/version")
        .map(|text| parse_proc_version(&text))
        .unwrap_or_default();

    let marker_present = std::path::Path::new("/var/run/reboot-required").exists();
    let packages = if marker_present {
        fs::read_to_string("/var/run/reboot-required.pkgs")
            .map(|text| {
                text.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let reboot_required = RebootRequiredInfo {
        marker_present,
        packages,
    };

    let aslr_mode = fs::read_to_string("/proc/sys/kernel/randomize_va_space")
        .ok()
        .and_then(|s| s.trim().parse().ok());

    let cmdline_text = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let notable_cmdline_flags = scan_notable_cmdline_flags(&cmdline_text);

    Ok(KernelRawData {
        tainted_raw,
        oom_kill_count,
        dmesg_error,
        build_info,
        reboot_required,
        aslr_mode,
        notable_cmdline_flags,
    })
}

/// Parse the single-integer contents of `/proc/sys/kernel/tainted`.
pub fn parse_tainted(text: &str) -> Result<u64, ModuleError> {
    text.trim().parse::<u64>().map_err(|e| ModuleError::Parse {
        what: "/proc/sys/kernel/tainted".to_string(),
        reason: e.to_string(),
    })
}

/// Which taint bits are set in a given raw value, in bit order.
pub fn active_taint_bits(tainted: u64) -> Vec<&'static TaintBit> {
    TAINT_BITS
        .iter()
        .filter(|b| (tainted >> b.bit) & 1 == 1)
        .collect()
}

/// Count OOM-killer lines in `dmesg` output text. Matches both the modern
/// ("Killed process") and older ("Kill process") kernel log phrasing —
/// both start with "Out of memory: Kill".
pub fn count_oom_kills(dmesg_text: &str) -> usize {
    dmesg_text
        .lines()
        .filter(|l| l.contains("Out of memory: Kill"))
        .count()
}

/// Parse `/proc/version`, e.g.:
/// "Linux version 6.8.0-31-generic (buildd@lcy02-amd64-119) (gcc (Ubuntu
/// 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42)
/// #31-Ubuntu SMP PREEMPT_DYNAMIC ..."
///
/// The two parenthesized groups (build user@host, then compiler info) can
/// themselves contain nested parens (GCC's own version string commonly
/// does — "gcc (Ubuntu ...) 13.2.0"), so this tracks paren *depth* rather
/// than naively matching the first ')' after each '(', which would cut
/// the compiler string short.
pub fn parse_proc_version(text: &str) -> KernelBuildInfo {
    let text = text.trim();

    let Some(first_open) = text.find('(') else {
        return KernelBuildInfo::default();
    };
    let Some(first_close) = find_matching_paren(text, first_open) else {
        return KernelBuildInfo::default();
    };
    let build_user_host = Some(text[first_open + 1..first_close].to_string());

    let rest = &text[first_close + 1..];
    let (compiler, build_tag) = match rest.find('(') {
        Some(second_open) => match find_matching_paren(rest, second_open) {
            Some(second_close) => {
                let compiler = Some(rest[second_open + 1..second_close].to_string());
                let tag = rest[second_close + 1..].trim();
                let build_tag = if tag.is_empty() {
                    None
                } else {
                    Some(tag.to_string())
                };
                (compiler, build_tag)
            }
            None => (None, None),
        },
        None => {
            let tag = rest.trim();
            let build_tag = if tag.is_empty() {
                None
            } else {
                Some(tag.to_string())
            };
            (None, build_tag)
        }
    };

    KernelBuildInfo {
        build_user_host,
        compiler,
        build_tag,
    }
}

/// Find the index of the `)` that closes the `(` at `open_idx`, tracking
/// nesting depth so inner parens don't terminate the match early.
fn find_matching_paren(text: &str, open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in text.char_indices() {
        if i < open_idx {
            continue;
        }
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Scan `/proc/cmdline` for a small set of well-known, diagnostically
/// notable boot parameters — not an exhaustive cmdline linter, just the
/// ones worth surfacing on their own.
pub fn scan_notable_cmdline_flags(cmdline: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    if cmdline.contains("mitigations=off") {
        found.push("mitigations=off");
    }
    if cmdline.split_whitespace().any(|t| t == "nomodeset") {
        found.push("nomodeset");
    }
    if cmdline
        .split_whitespace()
        .any(|t| t == "single" || t == "emergency")
    {
        found.push("single/emergency boot target");
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tainted_value() {
        assert_eq!(parse_tainted("0\n").unwrap(), 0);
        assert_eq!(parse_tainted("4609\n").unwrap(), 4609);
    }

    #[test]
    fn errors_on_malformed_tainted() {
        assert!(parse_tainted("not-a-number").is_err());
    }

    #[test]
    fn zero_has_no_active_bits() {
        assert!(active_taint_bits(0).is_empty());
    }

    // This exact value (4609) and its decoding (P, W, O) is the worked
    // example from the kernel's own tainted-kernels documentation --
    // https://docs.kernel.org/admin-guide/tainted-kernels.html -- not an
    // invented fixture.
    #[test]
    fn decodes_kernel_docs_worked_example() {
        let active = active_taint_bits(4609);
        let codes: Vec<&str> = active.iter().map(|b| b.code).collect();
        assert_eq!(codes, vec!["P", "W", "O"]);
    }

    #[test]
    fn single_bit_decodes_correctly() {
        // bit 4 = MCE = value 16
        let active = active_taint_bits(16);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].code, "M");
        assert_eq!(active[0].severity, Severity::Error);
    }

    #[test]
    fn counts_oom_kills_modern_format() {
        let text = "\
[12345.678] Out of memory: Killed process 1234 (myapp) total-vm:1048576kB
[12400.111] Out of memory: Killed process 5678 (otherapp) total-vm:2048576kB
";
        assert_eq!(count_oom_kills(text), 2);
    }

    #[test]
    fn counts_oom_kills_older_format() {
        let text = "[100.0] Out of memory: Kill process 42 (foo) score 900 or sacrifice child\n";
        assert_eq!(count_oom_kills(text), 1);
    }

    #[test]
    fn zero_oom_kills_in_clean_log() {
        let text = "[0.0] Linux version 6.8.0\n[1.0] Some other unrelated message\n";
        assert_eq!(count_oom_kills(text), 0);
    }

    #[test]
    fn parses_proc_version_simple_case() {
        // Real output from this sandbox's custom Firecracker kernel.
        let text = "Linux version 6.18.5-fc-v20 (builder@sandboxing) (gcc (GCC) 15.2.0, GNU ld (GNU Binutils) 2.46) #1 SMP PREEMPT_DYNAMIC @0\n";
        let info = parse_proc_version(text);
        assert_eq!(info.build_user_host.as_deref(), Some("builder@sandboxing"));
        // Nested parens inside the compiler group must not truncate it.
        assert_eq!(
            info.compiler.as_deref(),
            Some("gcc (GCC) 15.2.0, GNU ld (GNU Binutils) 2.46")
        );
        assert_eq!(info.build_tag.as_deref(), Some("#1 SMP PREEMPT_DYNAMIC @0"));
    }

    #[test]
    fn parses_proc_version_with_doubly_nested_parens() {
        // Typical Ubuntu-style /proc/version: both sub-components of the
        // compiler group have their own nested parens.
        let text = "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-119) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n";
        let info = parse_proc_version(text);
        assert_eq!(
            info.build_user_host.as_deref(),
            Some("buildd@lcy02-amd64-119")
        );
        assert_eq!(
            info.compiler.as_deref(),
            Some(
                "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38"
            )
        );
        assert!(info
            .build_tag
            .as_deref()
            .unwrap()
            .starts_with("#101-Ubuntu"));
    }

    #[test]
    fn parses_proc_version_malformed_input_gracefully() {
        let info = parse_proc_version("not a real version string");
        assert_eq!(info.build_user_host, None);
        assert_eq!(info.compiler, None);
    }

    #[test]
    fn scans_notable_cmdline_flags() {
        let flags =
            scan_notable_cmdline_flags("BOOT_IMAGE=/vmlinuz root=/dev/sda1 mitigations=off quiet");
        assert_eq!(flags, vec!["mitigations=off"]);

        let flags2 = scan_notable_cmdline_flags("root=/dev/sda1 nomodeset quiet splash");
        assert_eq!(flags2, vec!["nomodeset"]);

        let flags3 = scan_notable_cmdline_flags("root=/dev/sda1 quiet splash");
        assert!(flags3.is_empty());
    }

    #[test]
    fn cmdline_scan_does_not_false_positive_on_substrings() {
        // "single" appearing inside another word shouldn't match; only a
        // standalone whitespace-separated token counts.
        let flags = scan_notable_cmdline_flags("root=/dev/sda1 singleword=foo quiet");
        assert!(flags.is_empty());
    }
}
