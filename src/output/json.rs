// SPDX-License-Identifier: GPL-3.0-only

use serde::Serialize;

use crate::core::engine::Report;
use crate::models::Severity;

use super::common::RenderMeta;

/// Version of the JSON report layout, emitted as the top-level
/// `schema_version` field so scripts can check what they are reading.
///
/// The rule: adding a field never changes it (readers must ignore fields they
/// do not know); removing, renaming or re-typing a field, or changing what a
/// value means, bumps it by one. See ARCHITECTURE.md "JSON Renderer".
///
/// `linuxdoctor diff` reads this layout back (`src/diff/report.rs`): the fields it
/// reads are the ones it needs to compare, and `tests/diff_command.rs` feeds it a
/// report the real `audit` wrote, so a renamed or removed field fails there.
pub const SCHEMA_VERSION: u32 = 1;

/// Present only when `--min-severity` removed findings, so a filtered
/// report can never be mistaken for a complete one.
#[derive(Serialize)]
struct FilterJson {
    min_severity: Severity,
    hidden_findings: usize,
}

/// The report plus its schema version. `schema_version` comes first in the
/// output so it is the first thing a human or a streaming parser sees; the
/// report's own fields follow unchanged at the same level.
#[derive(Serialize)]
struct Envelope<'a> {
    schema_version: u32,
    /// The version of the program that wrote the report. Not part of the
    /// layout (`schema_version` is), but a record of where the findings came
    /// from: checks are added and thresholds change between versions.
    linuxdoctor_version: &'a str,
    /// The profile the report was judged with (the report knows: it is the
    /// one `profile::apply` was given). Absent when none was chosen, so a
    /// report written without a profile is exactly what it always was.
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<FilterJson>,
    #[serde(flatten)]
    report: &'a Report,
}

/// Serializes a Report to pretty JSON. Formatting only — no diagnostics.
/// See ARCHITECTURE.md "Output Engine" / "JSON Renderer".
pub fn render(report: &Report) -> serde_json::Result<String> {
    render_with(report, &RenderMeta::default())
}

/// Like `render`, also recording a `--min-severity` filter when one was
/// applied (`filter: { min_severity, hidden_findings }`).
pub fn render_with(report: &Report, meta: &RenderMeta) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&Envelope {
        schema_version: SCHEMA_VERSION,
        linuxdoctor_version: meta.tool_version,
        profile: report.profile.map(|p| p.name()),
        filter: meta.filter.map(|f| FilterJson {
            min_severity: f.min_severity,
            hidden_findings: f.hidden,
        }),
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
            profile: None,
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
    fn unfiltered_report_has_no_filter_key() {
        assert!(parsed(&report()).get("filter").is_none());
    }

    #[test]
    fn filtered_report_records_the_filter_after_the_version() {
        use crate::output::common::FilterInfo;
        let meta = RenderMeta {
            filter: Some(FilterInfo {
                min_severity: Severity::Warning,
                hidden: 12,
            }),
            ..RenderMeta::default()
        };
        let text = render_with(&report(), &meta).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["filter"]["min_severity"], "warning");
        assert_eq!(json["filter"]["hidden_findings"], 12);
        assert_eq!(json["schema_version"], serde_json::json!(SCHEMA_VERSION));
        assert!(json["results"].is_array(), "report fields are still there");
        // `schema_version`, then who wrote the report, then the filter.
        let third_key = text.lines().nth(3).unwrap().trim();
        assert!(third_key.starts_with("\"filter\":"), "{third_key}");
    }

    #[test]
    fn the_report_says_which_version_wrote_it_right_after_the_layout_version() {
        let meta = RenderMeta {
            tool_version: "9.9.9",
            ..RenderMeta::default()
        };
        let text = render_with(&report(), &meta).unwrap();
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        assert!(lines[1].starts_with("\"schema_version\":"), "{}", lines[1]);
        assert_eq!(lines[2], "\"linuxdoctor_version\": \"9.9.9\",");
        // And by default it is the version of this build.
        let json = parsed(&report());
        assert_eq!(json["linuxdoctor_version"], crate::VERSION);
    }

    #[test]
    fn a_report_written_without_a_profile_has_no_profile_key() {
        assert!(parsed(&report()).get("profile").is_none());
    }

    #[test]
    fn the_profile_is_recorded_right_after_the_version() {
        use crate::profile::Profile;
        let mut profiled = report();
        profiled.profile = Some(Profile::Hpc);
        let text = render(&profiled).unwrap();
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        assert!(lines[1].starts_with("\"schema_version\":"), "{}", lines[1]);
        assert!(
            lines[2].starts_with("\"linuxdoctor_version\":"),
            "{}",
            lines[2]
        );
        assert_eq!(lines[3], "\"profile\": \"hpc\",");
        // Every recorded word is one `Profile::from_name` gives back.
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let word = json["profile"].as_str().unwrap();
        assert_eq!(Profile::from_name(word), Some(Profile::Hpc));
    }

    #[test]
    fn profile_and_filter_can_both_be_recorded_in_that_order() {
        use crate::output::common::FilterInfo;
        use crate::profile::Profile;
        let meta = RenderMeta {
            filter: Some(FilterInfo {
                min_severity: Severity::Warning,
                hidden: 3,
            }),
            ..RenderMeta::default()
        };
        let mut profiled = report();
        profiled.profile = Some(Profile::Hpc);
        let text = render_with(&profiled, &meta).unwrap();
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        assert!(lines[3].starts_with("\"profile\":"), "{}", lines[3]);
        assert!(lines[4].starts_with("\"filter\":"), "{}", lines[4]);
    }

    #[test]
    fn only_the_two_version_keys_are_added_to_the_report() {
        let json = parsed(&report());
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
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
    }
}
