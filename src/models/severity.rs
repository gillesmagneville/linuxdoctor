// SPDX-License-Identifier: GPL-3.0-only

use serde::Serialize;
use std::fmt;

/// Operational impact of a finding. See ARCHITECTURE.md "Severity (canonical)"
/// for why this is four levels and not five.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl Severity {
    /// Compact terminal symbol used in the per-module status line.
    pub fn symbol(&self) -> &'static str {
        match self {
            Severity::Info => "\u{2713}",     // ✓
            Severity::Warning => "\u{26A0}",  // ⚠
            Severity::Error => "\u{2717}",    // ✗
            Severity::Critical => "\u{2757}", // ❗
        }
    }

    /// ANSI color code, kept hand-rolled per the "avoid a dependency for
    /// something this small" call in ARCHITECTURE.md.
    pub fn ansi_color(&self) -> &'static str {
        match self {
            Severity::Info => "\x1b[32m",       // green
            Severity::Warning => "\x1b[33m",    // yellow
            Severity::Error => "\x1b[31m",      // red
            Severity::Critical => "\x1b[1;31m", // bold red
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
            Severity::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_reflects_increasing_impact() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn serializes_lowercase() {
        let json = serde_json::to_string(&Severity::Warning).unwrap();
        assert_eq!(json, "\"warning\"");
    }
}
