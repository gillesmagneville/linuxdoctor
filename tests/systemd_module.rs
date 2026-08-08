// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::systemd::analyze::analyze;
use linuxdoctor::modules::systemd::collect::{parse_failed_units, SystemdRawData};

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
fn healthy_fixture_produces_only_info() {
    let data = SystemdRawData {
        system_state: "running".to_string(),
        failed_units: parse_failed_units(""),
    };

    let findings = analyze(&data, &test_context());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn degraded_fixture_reports_each_failed_unit() {
    let failed_text = "\
nginx.service                  loaded failed failed Nginx Web Server
backup-nightly.service         loaded failed failed Nightly backup job
";
    let data = SystemdRawData {
        system_state: "degraded".to_string(),
        failed_units: parse_failed_units(failed_text),
    };

    let findings = analyze(&data, &test_context());

    let sysd001 = findings.iter().find(|f| f.id == "SYSD001").unwrap();
    assert_eq!(sysd001.severity, Severity::Warning);

    let failed: Vec<_> = findings.iter().filter(|f| f.id == "SYSD002").collect();
    assert_eq!(failed.len(), 2);
    assert!(failed.iter().any(|f| f.title.contains("nginx.service")));
    assert!(failed
        .iter()
        .any(|f| f.title.contains("backup-nightly.service")));
}
