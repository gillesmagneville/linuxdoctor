// SPDX-License-Identifier: GPL-3.0-only

use serde::Serialize;

use super::category::Category;
use super::confidence::Confidence;
use super::severity::Severity;

/// A single diagnosis: an observation plus why it matters and what, if
/// anything, to do about it. See ARCHITECTURE.md "Findings".
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable identifier, e.g. "MEM002".
    pub id: String,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Observed facts as key/value pairs, e.g. ("swap_used_kb", "4200000").
    pub evidence: Vec<(String, String)>,
    pub explanation: String,
    pub recommendation: Option<String>,
    /// If this finding is about one specific sub-item within the module
    /// (a socket, a filesystem, a NUMA node, a failed unit...), this names
    /// that sub-item — e.g. "socket 0", "/", "node0", "nginx.service".
    /// Findings sharing the same instance value are grouped together by
    /// output modes that support drilling into detail (the TUI's
    /// submenus). `None` means this finding applies to the module as a
    /// whole and should always be shown at the module's top level.
    pub instance: Option<String>,
}

pub struct FindingBuilder {
    id: String,
    title: String,
    category: Category,
    severity: Severity,
    confidence: Confidence,
    evidence: Vec<(String, String)>,
    explanation: String,
    recommendation: Option<String>,
    instance: Option<String>,
}

impl Finding {
    pub fn builder(
        id: impl Into<String>,
        title: impl Into<String>,
        category: Category,
        severity: Severity,
        confidence: Confidence,
    ) -> FindingBuilder {
        FindingBuilder {
            id: id.into(),
            title: title.into(),
            category,
            severity,
            confidence,
            evidence: Vec::new(),
            explanation: String::new(),
            recommendation: None,
            instance: None,
        }
    }
}

impl FindingBuilder {
    pub fn evidence(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.push((key.into(), value.into()));
        self
    }

    pub fn explanation(mut self, text: impl Into<String>) -> Self {
        self.explanation = text.into();
        self
    }

    pub fn recommendation(mut self, text: impl Into<String>) -> Self {
        self.recommendation = Some(text.into());
        self
    }

    /// Marks this finding as belonging to a specific sub-item (socket,
    /// filesystem, node, unit...) rather than the module as a whole. Use
    /// the *same* instance string across every finding about that same
    /// sub-item (e.g. every finding about mount point "/" should pass
    /// `.instance("/")`) so they group together correctly.
    pub fn instance(mut self, name: impl Into<String>) -> Self {
        self.instance = Some(name.into());
        self
    }

    pub fn build(self) -> Finding {
        Finding {
            id: self.id,
            title: self.title,
            category: self.category,
            severity: self.severity,
            confidence: self.confidence,
            evidence: self.evidence,
            explanation: self.explanation,
            recommendation: self.recommendation,
            instance: self.instance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::confidence::Confidence;

    #[test]
    fn instance_defaults_to_none() {
        let f = Finding::builder(
            "TEST001",
            "Test",
            Category::Memory,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .build();
        assert_eq!(f.instance, None);
    }

    #[test]
    fn instance_builder_sets_value() {
        let f = Finding::builder(
            "TEST001",
            "Test",
            Category::Storage,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .instance("/")
        .build();
        assert_eq!(f.instance.as_deref(), Some("/"));
    }
}
