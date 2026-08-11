// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::core::error::ModuleError;

#[derive(Debug, Clone, PartialEq)]
pub struct NtpRawData {
    /// Whether the *kernel* reports the clock as synchronized
    /// (`adjtimex(3)`'s STA_UNSYNC flag, surfaced by systemd as
    /// `NTPSynchronized=`). Authoritative regardless of which daemon
    /// (systemd-timesyncd, chrony, ntpd) is doing the syncing, since they
    /// all ultimately update the same kernel clock state.
    pub ntp_synchronized: Option<bool>,
    /// Whether an NTP-capable service is enabled (`NTP=` — enabled, not
    /// necessarily currently synced).
    pub ntp_enabled: Option<bool>,
    /// Whether any NTP-capable service is available at all (`CanNTP=`).
    pub can_ntp: Option<bool>,
    /// Whether the hardware clock (RTC) is kept in local time rather
    /// than UTC (`LocalRTC=`) — a common dual-boot-with-Windows setting,
    /// not inherently wrong, but worth surfacing.
    pub local_rtc: Option<bool>,
    pub timezone: Option<String>,
}

/// Same marker systemd itself is built on — `timedatectl` is part of
/// systemd core, so if systemd isn't PID 1 it can't function either,
/// exactly like the Systemd module's own availability check.
pub fn systemd_available() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// Thin I/O wrapper: `timedatectl show` gives every fact this module
/// needs in clean key=value form (see analyze.rs for why `NTPSynchronized`
/// specifically is treated as somewhat less certain than a typical direct
/// observation).
pub fn collect() -> Result<NtpRawData, ModuleError> {
    let output = Command::new("timedatectl")
        .arg("show")
        .output()
        .map_err(|source| ModuleError::Command {
            command: "timedatectl show".to_string(),
            source,
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(ModuleError::Command {
            command: "timedatectl show".to_string(),
            source: std::io::Error::other(stderr),
        });
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_timedatectl_show(&text))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// Parse `timedatectl show` output: one `Key=value` pair per line. Pure
/// function, tested against fixture text.
pub fn parse_timedatectl_show(text: &str) -> NtpRawData {
    let fields: HashMap<&str, &str> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

    NtpRawData {
        ntp_synchronized: fields.get("NTPSynchronized").and_then(|v| parse_bool(v)),
        ntp_enabled: fields.get("NTP").and_then(|v| parse_bool(v)),
        can_ntp: fields.get("CanNTP").and_then(|v| parse_bool(v)),
        local_rtc: fields.get("LocalRTC").and_then(|v| parse_bool(v)),
        timezone: fields.get("Timezone").map(|v| v.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_SYNCED: &str = "\
Timezone=Europe/Berlin
LocalRTC=no
CanNTP=yes
NTP=yes
NTPSynchronized=yes
TimeUSec=Tue 2026-04-14 10:00:00 UTC
RTCTimeUSec=Tue 2026-04-14 10:00:00 UTC
";

    const FIXTURE_NOT_SYNCED: &str = "\
Timezone=Asia/Kolkata
LocalRTC=no
CanNTP=yes
NTP=yes
NTPSynchronized=no
";

    const FIXTURE_NO_NTP_SERVICE: &str = "\
Timezone=UTC
LocalRTC=no
CanNTP=no
NTP=no
NTPSynchronized=no
";

    #[test]
    fn parses_synced_fixture() {
        let data = parse_timedatectl_show(FIXTURE_SYNCED);
        assert_eq!(data.ntp_synchronized, Some(true));
        assert_eq!(data.ntp_enabled, Some(true));
        assert_eq!(data.can_ntp, Some(true));
        assert_eq!(data.local_rtc, Some(false));
        assert_eq!(data.timezone.as_deref(), Some("Europe/Berlin"));
    }

    #[test]
    fn parses_not_synced_fixture() {
        let data = parse_timedatectl_show(FIXTURE_NOT_SYNCED);
        assert_eq!(data.ntp_synchronized, Some(false));
        assert_eq!(data.can_ntp, Some(true));
    }

    #[test]
    fn parses_no_ntp_service_fixture() {
        let data = parse_timedatectl_show(FIXTURE_NO_NTP_SERVICE);
        assert_eq!(data.can_ntp, Some(false));
        assert_eq!(data.ntp_synchronized, Some(false));
    }

    #[test]
    fn missing_fields_are_none_not_an_error() {
        let data = parse_timedatectl_show("Timezone=UTC\n");
        assert_eq!(data.ntp_synchronized, None);
        assert_eq!(data.timezone.as_deref(), Some("UTC"));
    }

    #[test]
    fn empty_input_yields_all_none() {
        let data = parse_timedatectl_show("");
        assert_eq!(data.ntp_synchronized, None);
        assert_eq!(data.timezone, None);
    }
}
