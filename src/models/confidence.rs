// SPDX-License-Identifier: GPL-3.0-only

use serde::Serialize;

/// A confidence percentage plus the reason for it. Confidence must never
/// claim more certainty than the evidence actually shows — see
/// ARCHITECTURE.md "Confidence (canonical)".
#[derive(Debug, Clone, Serialize)]
pub struct Confidence {
    pub percent: u8,
    pub reason: String,
}

impl Confidence {
    pub fn new(percent: u8, reason: impl Into<String>) -> Self {
        Self {
            percent: percent.min(100),
            reason: reason.into(),
        }
    }

    pub fn direct_observation() -> Self {
        Self::new(100, "direct observation")
    }

    pub fn correlated(percent: u8) -> Self {
        debug_assert!((90..=95).contains(&percent));
        Self::new(percent, "multiple correlated observations")
    }

    pub fn strong_indication(percent: u8) -> Self {
        debug_assert!((75..=89).contains(&percent));
        Self::new(percent, "strong indication")
    }

    pub fn weak_indication(percent: u8) -> Self {
        debug_assert!((60..=74).contains(&percent));
        Self::new(percent, "weak indication")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_at_100() {
        let c = Confidence::new(255, "test");
        assert_eq!(c.percent, 100);
    }

    #[test]
    fn direct_observation_is_full_confidence() {
        assert_eq!(Confidence::direct_observation().percent, 100);
    }
}
