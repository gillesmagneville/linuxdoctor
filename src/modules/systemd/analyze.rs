// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{FailedUnit, SystemdRawData};

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &SystemdRawData, _ctx: &Context) -> Vec<Finding> {
    let mut findings = vec![system_state_finding(data)];

    for unit in &data.failed_units {
        findings.push(failed_unit_finding(unit));
    }

    findings
}

/// SYSD001 — always reported, including the failed-unit count as
/// evidence. Present even when everything is healthy, for the same
/// reason CPU005 always reports: absence of SYSD002 findings should never
/// be ambiguous with "this module didn't run".
fn system_state_finding(data: &SystemdRawData) -> Finding {
    let count = data.failed_units.len();

    let (severity, explanation) = match data.system_state.as_str() {
        "running" => (
            Severity::Info,
            "The system reports a healthy overall state.".to_string(),
        ),
        "degraded" => (
            Severity::Warning,
            format!(
                "The system reports a degraded state, meaning at least one \
                 unit has failed ({count} failed unit{s} found). See the \
                 individual failed-unit finding{s} below for details.",
                s = if count == 1 { "" } else { "s" },
            ),
        ),
        other => (
            Severity::Info,
            format!(
                "The system reports state '{other}'. This can be a normal \
                 transitional state (e.g. during boot or shutdown) rather \
                 than a problem on its own."
            ),
        ),
    };

    Finding::builder(
        "SYSD001",
        "System State",
        Category::Systemd,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("state", data.system_state.clone())
    .evidence("failed_units_count", count.to_string())
    .explanation(explanation)
    .build()
}

/// SYSD002 — one finding per failed unit. Kept at a uniform Warning
/// rather than trying to guess per-unit importance from `systemctl`
/// output alone, which this tool has no reliable way to judge.
fn failed_unit_finding(unit: &FailedUnit) -> Finding {
    let description = if unit.description.is_empty() {
        "(no description)"
    } else {
        &unit.description
    };

    Finding::builder(
        "SYSD002",
        format!("Failed Unit \u{2014} {}", unit.name),
        Category::Systemd,
        Severity::Warning,
        Confidence::direct_observation(),
    )
    .instance(unit.name.clone())
    .evidence("unit", unit.name.clone())
    .evidence("load_state", unit.load_state.clone())
    .evidence("active_state", unit.active_state.clone())
    .evidence("sub_state", unit.sub_state.clone())
    .explanation(format!(
        "{} ({description}) is in a failed state (load={}, active={}, sub={}).",
        unit.name, unit.load_state, unit.active_state, unit.sub_state,
    ))
    .recommendation(format!(
        "Check recent logs with `journalctl -u {}` to see why it failed, \
         and `systemctl restart {}` once the underlying issue is fixed.",
        unit.name, unit.name,
    ))
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "test".into(),
            distro: None,
            architecture: "x86_64".into(),
            cpu_count: 4,
            mem_total_kb: 16_384_000,
            boot_time_unix: 0,
        }
    }

    fn unit(name: &str) -> FailedUnit {
        FailedUnit {
            name: name.to_string(),
            load_state: "loaded".to_string(),
            active_state: "failed".to_string(),
            sub_state: "failed".to_string(),
            description: "Test Unit".to_string(),
        }
    }

    #[test]
    fn healthy_state_produces_only_info() {
        let data = SystemdRawData {
            system_state: "running".to_string(),
            failed_units: vec![],
        };
        let findings = analyze(&data, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "SYSD001");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn degraded_state_is_warning() {
        let data = SystemdRawData {
            system_state: "degraded".to_string(),
            failed_units: vec![unit("nginx.service")],
        };
        let findings = analyze(&data, &ctx());
        let sysd001 = findings.iter().find(|f| f.id == "SYSD001").unwrap();
        assert_eq!(sysd001.severity, Severity::Warning);
        assert!(sysd001
            .evidence
            .iter()
            .any(|(k, v)| k == "failed_units_count" && v == "1"));
    }

    #[test]
    fn one_finding_per_failed_unit() {
        let data = SystemdRawData {
            system_state: "degraded".to_string(),
            failed_units: vec![unit("a.service"), unit("b.service")],
        };
        let findings = analyze(&data, &ctx());
        assert_eq!(findings.iter().filter(|f| f.id == "SYSD002").count(), 2);
    }

    #[test]
    fn transitional_state_is_info_not_warning() {
        let data = SystemdRawData {
            system_state: "starting".to_string(),
            failed_units: vec![],
        };
        let findings = analyze(&data, &ctx());
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn confidence_never_reported_below_60() {
        let data = SystemdRawData {
            system_state: "degraded".to_string(),
            failed_units: vec![unit("x.service")],
        };
        for f in analyze(&data, &ctx()) {
            assert!(f.confidence.percent >= 60);
        }
    }
}
