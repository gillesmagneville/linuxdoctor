// SPDX-License-Identifier: GPL-3.0-only

//! End-to-end check of the JSON report envelope: the real binary, real
//! `/proc`, only the memory module (always available, fast).

use std::process::Command;

fn audit_json() -> (String, serde_json::Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        // Never the configuration file of whoever runs the tests.
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .args(["audit", "--modules", "memory", "--output", "json"])
        .output()
        .expect("linuxdoctor binary should start");
    let text = String::from_utf8(output.stdout).expect("JSON output is UTF-8");
    let json = serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON ({e}): {text}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (text, json)
}

#[test]
fn json_report_declares_its_schema_version_first() {
    let (text, json) = audit_json();
    assert_eq!(
        json["schema_version"],
        serde_json::json!(linuxdoctor::output::json::SCHEMA_VERSION)
    );
    let first_key_line = text.lines().nth(1).unwrap_or_default().trim();
    assert!(
        first_key_line.starts_with("\"schema_version\":"),
        "first key line was: {first_key_line}"
    );
}

#[test]
fn json_report_keeps_the_documented_top_level_shape() {
    let (_, json) = audit_json();
    let mut keys: Vec<&str> = json
        .as_object()
        .expect("top level is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "context",
            "linuxdoctor_version",
            "results",
            "schema_version"
        ]
    );
    assert_eq!(json["linuxdoctor_version"], linuxdoctor::VERSION);
    let first = &json["results"][0];
    for key in ["module_id", "findings", "error", "skipped", "notes"] {
        assert!(first.get(key).is_some(), "missing {key} in module result");
    }
}
