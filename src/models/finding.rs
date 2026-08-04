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
        }
    }
}
