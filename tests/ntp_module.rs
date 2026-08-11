// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::ntp::analyze::analyze;
use linuxdoctor::modules::ntp::collect::parse_timedatectl_show;

fn test_context() -> Context {
    Context {
        hostname: "test-host".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some("Test Linux".into()),
        architecture: "x86_64".into(),
        cpu_count: 4,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    }
}

#[test]
fn healthy_synced_fixture_produces_only_info_findings() {
    let text = "\
Timezone=Europe/Berlin
LocalRTC=no
CanNTP=yes
NTP=yes
NTPSynchronized=yes
";
    let data = parse_timedatectl_show(text);
    let findings = analyze(&data, &test_context());
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
}

#[test]
fn no_ntp_service_fixture_produces_warning() {
    let text = "\
Timezone=UTC
LocalRTC=no
CanNTP=no
NTP=no
NTPSynchronized=no
";
    let data = parse_timedatectl_show(text);
    let findings = analyze(&data, &test_context());
    let ntp001 = findings.iter().find(|f| f.id == "NTP001").unwrap();
    assert_eq!(ntp001.severity, Severity::Warning);
}

#[test]
fn local_rtc_fixture_flagged_but_not_alarming() {
    let text = "\
Timezone=America/New_York
LocalRTC=yes
CanNTP=yes
NTP=yes
NTPSynchronized=yes
";
    let data = parse_timedatectl_show(text);
    let findings = analyze(&data, &test_context());
    let ntp002 = findings.iter().find(|f| f.id == "NTP002").unwrap();
    assert_eq!(ntp002.severity, Severity::Info);
    assert!(ntp002.explanation.contains("dual-boot"));
}
