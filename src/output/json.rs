use crate::core::engine::Report;

/// Serializes a Report to pretty JSON. Formatting only — no diagnostics.
/// See ARCHITECTURE.md "Output Engine" / "JSON Renderer".
pub fn render(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}
