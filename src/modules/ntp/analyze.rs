// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::NtpRawData;

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &NtpRawData, _ctx: &Context) -> Vec<Finding> {
    vec![sync_status_finding(data), rtc_mode_finding(data)]
}

/// NTP001 — always reported. `NTPSynchronized` comes from the kernel's
/// own STA_UNSYNC flag (authoritative regardless of which daemon is
/// syncing), but it's a known false negative with chrony/ntpd
/// configurations that don't set the kernel sync flag (e.g. missing
/// `rtcsync` in chrony.conf, or ntpd run with `-x`) — documented in
/// vendor support cases, not something this tool can rule out from here.
/// That's why this stays at `strong_indication` rather than
/// `direct_observation` once something looks wrong: the raw value is
/// certain, what it implies is very likely but not 100% guaranteed.
fn sync_status_finding(data: &NtpRawData) -> Finding {
    let (severity, confidence, explanation) = match (data.ntp_synchronized, data.can_ntp) {
        (Some(true), _) => (
            Severity::Info,
            Confidence::direct_observation(),
            "The kernel reports the system clock as synchronized.".to_string(),
        ),
        (Some(false), Some(false)) => (
            Severity::Warning,
            Confidence::strong_indication(82),
            "No NTP-capable time sync service is available at all, and the \
             clock is not synchronized. Without correction, the clock will \
             drift over time — this commonly breaks TLS certificate \
             validation, log correlation across hosts, and anything relying \
             on consistent timestamps."
                .to_string(),
        ),
        (Some(false), Some(true)) => (
            Severity::Warning,
            Confidence::strong_indication(75),
            "An NTP-capable service is available, but the kernel does not \
             report the clock as synchronized. This is usually a real sync \
             problem (check connectivity to time servers), but is also a \
             known false negative with some chrony/ntpd configurations that \
             don't update the kernel's sync flag (e.g. chrony missing \
             `rtcsync`, or ntpd run with `-x`) — worth cross-checking with \
             `chronyc tracking` or `ntpq -p` before assuming the clock is \
             actually drifting."
                .to_string(),
        ),
        _ => (
            Severity::Info,
            Confidence::weak_indication(60),
            "Could not determine clock synchronization status from \
             timedatectl."
                .to_string(),
        ),
    };

    let mut builder = Finding::builder(
        "NTP001",
        "Clock Synchronization Status",
        Category::Ntp,
        severity,
        confidence,
    );

    if let Some(v) = data.ntp_synchronized {
        builder = builder.evidence("ntp_synchronized", v.to_string());
    }
    if let Some(v) = data.ntp_enabled {
        builder = builder.evidence("ntp_enabled", v.to_string());
    }
    if let Some(v) = data.can_ntp {
        builder = builder.evidence("can_ntp", v.to_string());
    }

    builder = builder.explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "Ensure a time-sync service is installed and running \
             (systemd-timesyncd, chrony, or ntpd) and can reach its \
             configured servers. `timedatectl timesync-status` (for \
             timesyncd) or `chronyc tracking` (for chrony) gives more \
             detail than this summary.",
        );
    }

    builder.build()
}

/// NTP002 — always reported. Not inherently a problem either way: RTC in
/// local time is a common, deliberate choice on dual-boot Windows
/// systems. Purely informational context, not a verdict.
fn rtc_mode_finding(data: &NtpRawData) -> Finding {
    let explanation = match data.local_rtc {
        Some(true) => {
            "The hardware clock (RTC) is kept in local time rather than \
             UTC. This is a common, deliberate setting on systems that \
             dual-boot Windows (which historically assumes local-time RTC) \
             — worth confirming that's the reason here, since a \
             local-time RTC can cause clock jumps around daylight saving \
             time changes."
                .to_string()
        }
        Some(false) => "The hardware clock (RTC) is kept in UTC, the \
             recommended default — avoids daylight-saving-time-related \
             clock jumps."
            .to_string(),
        None => "Could not determine whether the hardware clock is in UTC \
             or local time."
            .to_string(),
    };

    let mut builder = Finding::builder(
        "NTP002",
        "RTC Time Mode",
        Category::Ntp,
        Severity::Info,
        Confidence::direct_observation(),
    );

    if let Some(v) = data.local_rtc {
        builder = builder.evidence("local_rtc", v.to_string());
    }
    if let Some(tz) = &data.timezone {
        builder = builder.evidence("timezone", tz.clone());
    }

    builder.explanation(explanation).build()
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

    fn data(ntp_synchronized: Option<bool>, can_ntp: Option<bool>) -> NtpRawData {
        NtpRawData {
            ntp_synchronized,
            ntp_enabled: can_ntp,
            can_ntp,
            local_rtc: Some(false),
            timezone: Some("UTC".to_string()),
        }
    }

    #[test]
    fn always_reports_both_checks() {
        let findings = analyze(&data(Some(true), Some(true)), &ctx());
        assert!(findings.iter().any(|f| f.id == "NTP001"));
        assert!(findings.iter().any(|f| f.id == "NTP002"));
    }

    #[test]
    fn synced_is_info_with_full_confidence() {
        let findings = analyze(&data(Some(true), Some(true)), &ctx());
        let ntp001 = findings.iter().find(|f| f.id == "NTP001").unwrap();
        assert_eq!(ntp001.severity, Severity::Info);
        assert_eq!(ntp001.confidence.percent, 100);
    }

    #[test]
    fn unsynced_with_no_ntp_service_is_warning() {
        let findings = analyze(&data(Some(false), Some(false)), &ctx());
        let ntp001 = findings.iter().find(|f| f.id == "NTP001").unwrap();
        assert_eq!(ntp001.severity, Severity::Warning);
        assert!(ntp001.recommendation.is_some());
    }

    #[test]
    fn unsynced_with_ntp_service_available_has_reduced_confidence() {
        let findings = analyze(&data(Some(false), Some(true)), &ctx());
        let ntp001 = findings.iter().find(|f| f.id == "NTP001").unwrap();
        assert_eq!(ntp001.severity, Severity::Warning);
        // Explicitly lower than a typical direct_observation (100%) or the
        // no-service case, reflecting the known false-negative caveat.
        assert!(ntp001.confidence.percent < 80);
        assert!(ntp001.explanation.contains("false negative"));
    }

    #[test]
    fn local_rtc_true_is_still_info_not_warning() {
        let mut d = data(Some(true), Some(true));
        d.local_rtc = Some(true);
        let findings = analyze(&d, &ctx());
        let ntp002 = findings.iter().find(|f| f.id == "NTP002").unwrap();
        assert_eq!(ntp002.severity, Severity::Info);
        assert!(ntp002.explanation.contains("dual-boot"));
    }

    #[test]
    fn confidence_never_reported_below_60() {
        for d in [
            data(Some(true), Some(true)),
            data(Some(false), Some(false)),
            data(Some(false), Some(true)),
            data(None, None),
        ] {
            for f in analyze(&d, &ctx()) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
