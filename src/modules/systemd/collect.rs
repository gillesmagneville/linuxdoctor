// SPDX-License-Identifier: GPL-3.0-only

use std::path::Path;

use crate::core::command::command;
use crate::core::error::ModuleError;

#[derive(Debug, Clone, PartialEq)]
pub struct FailedUnit {
    pub name: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SystemdRawData {
    pub system_state: String,
    pub failed_units: Vec<FailedUnit>,
}

/// Whether systemd is actually running as PID 1. `/run/systemd/system`
/// only exists in that case — the same check libsystemd's `sd_booted()`
/// uses. `systemctl` can be installed (e.g. from a base image) without
/// systemd being init at all, in which case every query below fails at
/// the D-Bus connection step, not at "not found".
pub fn systemd_available() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// Thin I/O wrapper: two systemctl queries, each with different error
/// semantics -- see the two functions below for why.
pub fn collect() -> Result<SystemdRawData, ModuleError> {
    let system_state = query_system_state()?;
    let failed_units = query_failed_units()?;
    Ok(SystemdRawData {
        system_state,
        failed_units,
    })
}

/// `systemctl is-system-running` exits non-zero for perfectly normal
/// states (e.g. "degraded" exits 1) -- the state string on stdout is what
/// matters here, not the exit code. Only a spawn failure is a real error.
fn query_system_state() -> Result<String, ModuleError> {
    let output = command("systemctl")
        .args(["is-system-running"])
        .output()
        .map_err(|source| ModuleError::Command {
            command: "systemctl is-system-running".to_string(),
            source,
        })?;
    let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(if state.is_empty() {
        "unknown".to_string()
    } else {
        state
    })
}

/// Unlike `is-system-running`, an empty result here is ambiguous between
/// "genuinely zero failed units" and "the query itself failed" -- so this
/// one *does* check the exit status, and surfaces stderr if it's non-zero,
/// rather than silently reporting a healthy-looking empty list.
fn query_failed_units() -> Result<Vec<FailedUnit>, ModuleError> {
    let output = command("systemctl")
        .args(["--failed", "--no-legend", "--plain", "--no-pager"])
        .output()
        .map_err(|source| ModuleError::Command {
            command: "systemctl --failed".to_string(),
            source,
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(ModuleError::Command {
            command: "systemctl --failed".to_string(),
            source: std::io::Error::other(stderr),
        });
    }

    Ok(parse_failed_units(&String::from_utf8_lossy(&output.stdout)))
}

/// Parse `systemctl --failed --no-legend --plain` output: one line per
/// failed unit, columns UNIT/LOAD/ACTIVE/SUB/DESCRIPTION. Pure function,
/// tested against fixture text. Empty input is not an error here --
/// zero failed units is the normal, healthy case.
pub fn parse_failed_units(text: &str) -> Vec<FailedUnit> {
    let mut units = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue; // malformed/short line -- skip defensively
        }
        units.push(FailedUnit {
            name: fields[0].to_string(),
            load_state: fields[1].to_string(),
            active_state: fields[2].to_string(),
            sub_state: fields[3].to_string(),
            description: fields[4..].join(" "),
        });
    }
    units
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_TWO_FAILED: &str = "\
nginx.service                  loaded failed failed Nginx Web Server
backup-nightly.service         loaded failed failed Nightly backup job
";

    #[test]
    fn parses_failed_units() {
        let units = parse_failed_units(FIXTURE_TWO_FAILED);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].name, "nginx.service");
        assert_eq!(units[0].load_state, "loaded");
        assert_eq!(units[0].active_state, "failed");
        assert_eq!(units[0].sub_state, "failed");
        assert_eq!(units[0].description, "Nginx Web Server");
        assert_eq!(units[1].name, "backup-nightly.service");
        assert_eq!(units[1].description, "Nightly backup job");
    }

    #[test]
    fn empty_input_is_zero_failed_units_not_an_error() {
        assert!(parse_failed_units("").is_empty());
    }

    #[test]
    fn skips_malformed_lines() {
        let text = "not enough fields\nnginx.service loaded failed failed Nginx\n";
        let units = parse_failed_units(text);
        assert_eq!(units.len(), 1);
    }

    #[test]
    fn handles_description_with_multiple_words() {
        let text = "foo.service loaded failed failed A Description With Many Words\n";
        let units = parse_failed_units(text);
        assert_eq!(units[0].description, "A Description With Many Words");
    }
}
