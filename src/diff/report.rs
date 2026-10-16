// SPDX-License-Identifier: GPL-3.0-only

//! Reading a report that `linuxdoctor audit --output json` wrote.
//!
//! These types are a reader's view of the file, deliberately separate from
//! the in-memory `Report`: they accept what an older or a newer LinuxDoctor
//! may have written (missing optional keys, extra keys) instead of
//! requiring the exact shape the running version produces.

use std::io::Read;

use serde::Deserialize;
use thiserror::Error;

use crate::models::Severity;
use crate::output::json::SCHEMA_VERSION;

/// Reports are a few hundred kilobytes at most; anything beyond this is not
/// one, and is refused rather than read into memory.
pub const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("could not read {name}: {reason}")]
    Read { name: String, reason: String },
    #[error("{name} is larger than {} MiB: that is not a LinuxDoctor report", MAX_REPORT_BYTES / (1024 * 1024))]
    TooLarge { name: String },
    #[error(
        "{name} is not a LinuxDoctor JSON report ({reason}); \
         write one with `linuxdoctor audit --output json`"
    )]
    Invalid { name: String, reason: String },
    #[error(
        "{name} uses report format {found}, newer than the format {supported} this version \
         of LinuxDoctor reads; upgrade LinuxDoctor to compare it"
    )]
    TooNew {
        name: String,
        found: u64,
        supported: u32,
    },
}

/// A whole report, as read from a file.
#[derive(Debug, Clone, Deserialize)]
pub struct ReportFile {
    /// Absent in reports that predate the field; their layout is the same
    /// as format 1.
    #[serde(default)]
    pub schema_version: u32,
    /// The version of LinuxDoctor that wrote the report. Absent from the
    /// reports of versions that did not record it (1.8.0 and earlier).
    #[serde(default)]
    pub linuxdoctor_version: Option<String>,
    pub context: ContextFile,
    pub results: Vec<ModuleFile>,
    /// Present when the report was written with `--min-severity`, which
    /// removed the findings below it.
    #[serde(default)]
    pub filter: Option<FilterFile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContextFile {
    pub hostname: String,
    #[serde(default)]
    pub kernel_version: String,
    #[serde(default)]
    pub distro: Option<String>,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub cpu_count: u64,
    #[serde(default)]
    pub mem_total_kb: u64,
    #[serde(default)]
    pub boot_time_unix: u64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct FilterFile {
    pub min_severity: Severity,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModuleFile {
    pub module_id: String,
    #[serde(default)]
    pub findings: Vec<FindingFile>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub skipped: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FindingFile {
    pub id: String,
    #[serde(default)]
    pub title: String,
    pub severity: Severity,
    #[serde(default)]
    pub evidence: Vec<(String, String)>,
    #[serde(default)]
    pub instance: Option<String>,
}

/// Parses the text of a report. `name` is only used in error messages.
pub fn parse(text: &str, name: &str) -> Result<ReportFile, ReportError> {
    let invalid = |reason: String| ReportError::Invalid {
        name: name.to_string(),
        reason,
    };
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| invalid(e.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("the top level is not an object".to_string()))?;

    // Check the version before the shape: a newer layout may well not fit
    // the types below, and "too new" is the more useful thing to say.
    if let Some(found) = object.get("schema_version").and_then(|v| v.as_u64()) {
        if found > u64::from(SCHEMA_VERSION) {
            return Err(ReportError::TooNew {
                name: name.to_string(),
                found,
                supported: SCHEMA_VERSION,
            });
        }
    }
    serde_json::from_value(value).map_err(|e| invalid(e.to_string()))
}

/// Reads and parses a report from `source`: a file path, or `-` for
/// standard input.
pub fn read(source: &str) -> Result<ReportFile, ReportError> {
    let name = display_name(source);
    let read_error = |e: std::io::Error| ReportError::Read {
        name: name.clone(),
        reason: e.to_string(),
    };
    let mut bytes = Vec::new();
    let limit = MAX_REPORT_BYTES + 1;
    if source == "-" {
        std::io::stdin()
            .lock()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(read_error)?;
    } else {
        std::fs::File::open(source)
            .map_err(read_error)?
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(read_error)?;
    }
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err(ReportError::TooLarge { name });
    }
    let text = String::from_utf8(bytes).map_err(|_| ReportError::Invalid {
        name: name.clone(),
        reason: "not valid UTF-8 text".to_string(),
    })?;
    parse(&text, &name)
}

/// How a source is named in messages and in the comparison: its path as
/// typed, or a description of standard input.
pub fn display_name(source: &str) -> String {
    if source == "-" {
        "standard input".to_string()
    } else {
        source.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"{
        "schema_version": 1,
        "context": {"hostname": "web01"},
        "results": [{"module_id": "memory"}]
    }"#;

    #[test]
    fn a_minimal_report_parses_with_defaults() {
        let report = parse(MINIMAL, "r.json").unwrap();
        assert_eq!(report.context.hostname, "web01");
        assert_eq!(report.context.boot_time_unix, 0);
        assert_eq!(report.results[0].module_id, "memory");
        assert!(report.results[0].findings.is_empty());
        assert!(!report.results[0].skipped);
        assert!(report.filter.is_none());
    }

    #[test]
    fn the_version_that_wrote_the_report_is_read_when_it_is_there() {
        let with = r#"{
            "schema_version": 1,
            "linuxdoctor_version": "1.9.0",
            "context": {"hostname": "web01"},
            "results": []
        }"#;
        assert_eq!(
            parse(with, "r.json")
                .unwrap()
                .linuxdoctor_version
                .as_deref(),
            Some("1.9.0")
        );
        // Reports from versions that did not record it do not say.
        assert_eq!(parse(MINIMAL, "r.json").unwrap().linuxdoctor_version, None);
        // A value of another type is a report this version cannot read.
        let wrong = with.replace("\"1.9.0\"", "180");
        assert!(parse(&wrong, "r.json").is_err());
    }

    #[test]
    fn keys_this_version_does_not_know_are_ignored() {
        let text = r#"{
            "schema_version": 1,
            "something_new": [1, 2],
            "context": {"hostname": "h", "future_fact": true},
            "results": [{
                "module_id": "cpu", "future": 1,
                "findings": [{
                    "id": "CPU001", "title": "t", "severity": "warning",
                    "confidence": {"percent": 90, "reason": "x"},
                    "evidence": [["load", "3.5"]], "explanation": "e",
                    "recommendation": null, "instance": "socket 0", "extra": 1
                }]
            }]
        }"#;
        let report = parse(text, "r").unwrap();
        let finding = &report.results[0].findings[0];
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.instance.as_deref(), Some("socket 0"));
        assert_eq!(finding.evidence, [("load".to_string(), "3.5".to_string())]);
    }

    #[test]
    fn a_report_without_schema_version_is_read_as_format_one() {
        let text = r#"{"context": {"hostname": "h"}, "results": []}"#;
        assert_eq!(parse(text, "old.json").unwrap().schema_version, 0);
    }

    #[test]
    fn a_newer_format_is_refused_before_its_shape_is_judged() {
        // The body is deliberately not the current shape: "too new" must win.
        let text = r#"{"schema_version": 2, "totally": "different"}"#;
        match parse(text, "future.json") {
            Err(ReportError::TooNew {
                found, supported, ..
            }) => {
                assert_eq!(found, 2);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected TooNew, got {other:?}"),
        }
    }

    #[test]
    fn things_that_are_not_reports_are_refused_with_a_hint() {
        for text in [
            "",
            "not json",
            "[1, 2]",
            "{}",
            r#"{"context": {"hostname": "h"}}"#,
            r#"{"context": {"hostname": "h"}, "results": [{"module_id": "m",
               "findings": [{"id": "X", "severity": "fatal"}]}]}"#,
        ] {
            let error = parse(text, "x.json").unwrap_err().to_string();
            assert!(error.contains("x.json"), "{error}");
            assert!(error.contains("audit --output json"), "{error}");
        }
    }

    #[test]
    fn the_filter_object_is_read() {
        let text = r#"{"schema_version": 1,
            "filter": {"min_severity": "warning", "hidden_findings": 12},
            "context": {"hostname": "h"}, "results": []}"#;
        let filter = parse(text, "f").unwrap().filter.unwrap();
        assert_eq!(filter.min_severity, Severity::Warning);
    }

    #[test]
    fn a_missing_file_names_the_file() {
        let error = read("/definitely/not/here.json").unwrap_err().to_string();
        assert!(error.contains("/definitely/not/here.json"), "{error}");
    }

    #[test]
    fn standard_input_has_a_readable_name() {
        assert_eq!(display_name("-"), "standard input");
        assert_eq!(display_name("a/b.json"), "a/b.json");
    }
}
