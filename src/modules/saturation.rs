// SPDX-License-Identifier: GPL-3.0-only

//! How full a table of the kernel is, and how loud to be about it.
//!
//! The kernel keeps a few tables with a fixed size: the open files, the
//! processes and threads, the tracked connections. Nothing is wrong while
//! they have room. When one is full, the next program that asks for an
//! entry is refused -- `Too many open files in system`, `Resource
//! temporarily unavailable`, a dropped packet -- and services fail in ways
//! that do not point back to the table. This is the one rule, for all of
//! them, of when "getting full" becomes a finding.
//!
//! What is read is a counter at one instant, so a reading near the limit is
//! a strong indication and never a certainty: the table may have been
//! emptied a second later.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::models::{Confidence, Severity};

/// From this share of the limit on, a table is getting full.
pub const NEAR_PERCENT: u128 = 80;

/// From this share on, the next burst is enough to fill it.
pub const FULL_PERCENT: u128 = 95;

/// Longest value read from a file of `/proc/sys`: they hold a few numbers.
const MAX_READ: u64 = 256;

/// A table's use against its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fill {
    pub used: u64,
    pub limit: u64,
}

/// How close to full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Room to spare.
    Ample,
    /// [`NEAR_PERCENT`] or more.
    Near,
    /// [`FULL_PERCENT`] or more.
    Full,
}

impl Fill {
    /// The share used, in whole percent, rounded down; `None` for a limit of
    /// zero, which has no share. More than 100 when the table holds more than
    /// its limit (a counter can briefly overshoot).
    pub fn percent(&self) -> Option<u64> {
        if self.limit == 0 {
            return None;
        }
        let percent = u128::from(self.used) * 100 / u128::from(self.limit);
        Some(u64::try_from(percent).unwrap_or(u64::MAX))
    }

    /// `None` when there is no limit to compare with. The comparison is exact
    /// (not on the rounded percent), and cannot overflow: a limit of
    /// `i64::MAX` is common.
    pub fn level(&self) -> Option<Level> {
        if self.limit == 0 {
            return None;
        }
        let used = u128::from(self.used) * 100;
        let limit = u128::from(self.limit);
        Some(if used >= limit * FULL_PERCENT {
            Level::Full
        } else if used >= limit * NEAR_PERCENT {
            Level::Near
        } else {
            Level::Ample
        })
    }
}

impl Level {
    pub fn severity(self) -> Severity {
        match self {
            Level::Ample => Severity::Info,
            Level::Near => Severity::Warning,
            Level::Full => Severity::Error,
        }
    }

    /// A figure that is exact is certain; that it is a problem is not.
    pub fn confidence(self) -> Confidence {
        match self {
            Level::Ample => Confidence::direct_observation(),
            Level::Near | Level::Full => Confidence::strong_indication(85),
        }
    }
}

/// Twice `limit`, for a limit to raise; `i64::MAX` is the most a `sysctl` of
/// this kind takes.
pub fn doubled(limit: u64) -> u64 {
    limit.saturating_mul(2).min(i64::MAX as u64)
}

/// The text of a file of `/proc`, at most [`MAX_READ`] bytes of it; `None`
/// when it cannot be read.
pub fn read_small(path: &Path) -> Option<String> {
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(MAX_READ)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// A file holding one whole number, as the files of `/proc/sys` do.
pub fn parse_number(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fill(used: u64, limit: u64) -> Fill {
        Fill { used, limit }
    }

    #[test]
    fn the_share_is_in_whole_percent_rounded_down() {
        for (used, limit, percent) in [
            (0, 100, 0),
            (1, 100, 1),
            (79, 100, 79),
            (80, 100, 80),
            (99, 100, 99),
            (100, 100, 100),
            (119, 819_675, 0),
            (1, 3, 33),
            (2, 3, 66),
            (101, 100, 101),
            (250, 100, 250),
        ] {
            assert_eq!(fill(used, limit).percent(), Some(percent), "{used}/{limit}");
        }
        assert_eq!(fill(5, 0).percent(), None);
        assert_eq!(fill(0, 0).percent(), None);
    }

    #[test]
    fn the_share_does_not_overflow_with_the_largest_numbers() {
        // `fs.file-max` is 9223372036854775807 on some systems.
        let max = i64::MAX as u64;
        assert_eq!(fill(1000, max).percent(), Some(0));
        assert_eq!(fill(max, max).percent(), Some(100));
        assert_eq!(fill(u64::MAX, 1).percent(), Some(u64::MAX));
        assert_eq!(fill(max, max).level(), Some(Level::Full));
        assert_eq!(fill(1000, max).level(), Some(Level::Ample));
        assert_eq!(fill(u64::MAX, u64::MAX).level(), Some(Level::Full));
    }

    #[test]
    fn a_table_is_near_full_at_eighty_percent_and_full_at_ninety_five() {
        for (used, level) in [
            (0, Level::Ample),
            (79, Level::Ample),
            (80, Level::Near),
            (94, Level::Near),
            (95, Level::Full),
            (100, Level::Full),
            (150, Level::Full),
        ] {
            assert_eq!(fill(used, 100).level(), Some(level), "{used}/100");
        }
    }

    #[test]
    fn the_thresholds_are_exact_not_rounded() {
        // 79.9% rounds down to 79, and is not near; 80.0% is.
        assert_eq!(fill(799, 1000).level(), Some(Level::Ample));
        assert_eq!(fill(800, 1000).level(), Some(Level::Near));
        assert_eq!(fill(949, 1000).level(), Some(Level::Near));
        assert_eq!(fill(950, 1000).level(), Some(Level::Full));
        // Whole numbers do not divide evenly: 4/5 is exactly 80%.
        assert_eq!(fill(4, 5).level(), Some(Level::Near));
        assert_eq!(fill(3, 4).level(), Some(Level::Ample));
        assert_eq!(fill(19, 20).level(), Some(Level::Full));
        assert_eq!(fill(18, 19).level(), Some(Level::Near));
        assert_eq!(fill(17, 19).level(), Some(Level::Near));
    }

    #[test]
    fn a_limit_of_zero_has_no_level() {
        assert_eq!(fill(0, 0).level(), None);
        assert_eq!(fill(10, 0).level(), None);
    }

    #[test]
    fn each_level_has_its_severity_and_confidence() {
        assert_eq!(Level::Ample.severity(), Severity::Info);
        assert_eq!(Level::Near.severity(), Severity::Warning);
        assert_eq!(Level::Full.severity(), Severity::Error);
        assert_eq!(Level::Ample.confidence().percent, 100);
        assert_eq!(Level::Near.confidence().percent, 85);
        assert_eq!(Level::Full.confidence().percent, 85);
    }

    #[test]
    fn a_limit_to_raise_is_doubled_up_to_what_sysctl_takes() {
        let max = i64::MAX as u64;
        assert_eq!(doubled(0), 0);
        assert_eq!(doubled(1), 2);
        assert_eq!(doubled(100), 200);
        assert_eq!(doubled(819_675), 1_639_350);
        assert_eq!(doubled(max / 2), max - 1);
        assert_eq!(doubled(max / 2 + 1), max);
        assert_eq!(doubled(max), max);
        assert_eq!(doubled(u64::MAX), max);
    }

    #[test]
    fn a_number_is_a_whole_number_with_blanks_around() {
        for (text, number) in [
            ("32768\n", Some(32768)),
            ("  7 ", Some(7)),
            ("0", Some(0)),
            ("18446744073709551615", Some(u64::MAX)),
            ("18446744073709551616", None),
            ("-1", None),
            ("1.5", None),
            ("", None),
            ("\n", None),
            ("max", None),
            ("1 2", None),
        ] {
            assert_eq!(parse_number(text), number, "{text:?}");
        }
    }

    #[test]
    fn a_file_is_read_up_to_a_bound() {
        let dir = std::env::temp_dir().join(format!(
            "linuxdoctor-saturation-read-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("small"), "12\n").unwrap();
        fs::write(dir.join("big"), "7".repeat(100_000)).unwrap();
        assert_eq!(read_small(&dir.join("small")).as_deref(), Some("12\n"));
        assert_eq!(read_small(&dir.join("big")).unwrap().len(), 256);
        assert_eq!(read_small(&dir.join("absent")), None);
        // Not text: not read.
        fs::write(dir.join("binary"), [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(read_small(&dir.join("binary")), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
