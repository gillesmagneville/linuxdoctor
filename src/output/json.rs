// SPDX-License-Identifier: GPL-3.0-only

use serde::Serialize;

use crate::core::engine::Report;

/// Version of the JSON report layout, emitted as the top-level
/// `schema_version` field so scripts can check what they are reading.
///
/// The rule: adding a field never changes it (readers must ignore fields they
/// do not know); removing, renaming or re-typing a field, or changing what a
/// value means, bumps it by one. See ARCHITECTURE.md "JSON Renderer".
pub const SCHEMA_VERSION: u32 = 1;

/// The report plus its schema version. `schema_version` comes first in the
/// output so it is the first thing a human or a streaming parser sees; the
/// report's own fields follow unchanged at the same level.
#[derive(Serialize)]
struct Envelope<'a> {
    schema_version: u32,
    #[serde(flatten)]
    report: &'a Report,
}

/// Serializes a Report to pretty JSON. Formatting only — no diagnostics.
/// See ARCHITECTURE.md "Output Engine" / "JSON Renderer".
pub fn render(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&Envelope {
        schema_version: SCHEMA_VERSION,
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::Context;
    use crate::core::engine::ModuleRunResult;
    use crate::models::{Category, Confidence, Finding, Severity};

    fn report() -> Report {
        Report {
            context: Context {
                hostname: "web01".into(),
                kernel_version: "6.8.0".into(),
                distro: None,
                architecture: "x86_64".into(),
                cpu_count: 4,
                mem_total_kb: 16_384_000,
                boot_time_unix: 0,
            },
            results: vec![ModuleRunResult {
                module_id: "memory",
                findings: vec![Finding::builder(
                    "MEM001",
                    "Kernel Swappiness Setting",
                    Category::Memory,
                    Severity::Info,
                    Confidence::direct_observation(),
                )
                .explanation("fine")
                .build()],
                error: None,
                skipped: false,
                notes: vec![],
            }],
        }
    }

    fn parsed(report: &Report) -> serde_json::Value {
        serde_json::from_str(&render(report).unwrap()).unwrap()
    }

    #[test]
    fn schema_version_is_present_and_numeric() {
        let json = parsed(&report());
        assert_eq!(json["schema_version"], serde_json::json!(SCHEMA_VERSION));
        assert!(json["schema_version"].is_u64());
    }

    #[test]
    fn schema_version_is_the_first_key() {
        let text = render(&report()).unwrap();
        let first_key = text
            .lines()
            .nth(1)
            .expect("pretty JSON has a second line")
            .trim();
        assert!(
            first_key.starts_with("\"schema_version\":"),
            "first key was: {first_key}"
        );
    }

    #[test]
    fn report_fields_stay_at_the_top_level() {
        let json = parsed(&report());
        assert_eq!(json["context"]["hostname"], "web01");
        assert_eq!(json["results"][0]["module_id"], "memory");
        assert_eq!(json["results"][0]["findings"][0]["id"], "MEM001");
        assert!(json["results"][0]["notes"].is_array());
    }

    #[test]
    fn exactly_one_new_top_level_key() {
        let json = parsed(&report());
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["context", "results", "schema_version"]);
    }
}
