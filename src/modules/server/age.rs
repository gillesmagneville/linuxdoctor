// SPDX-License-Identifier: GPL-3.0-only

//! How long ago something happened, in words.

/// Seconds in a minute, an hour and a day.
pub const MINUTE: u64 = 60;
pub const HOUR: u64 = 60 * MINUTE;
pub const DAY: u64 = 24 * HOUR;

/// `1 hour`, `3 days`: the biggest unit of minutes, hours or days that fits
/// at least once, rounded down. Under a minute it is `less than a minute`.
pub fn age_text(seconds: u64) -> String {
    let (count, unit) = if seconds >= DAY {
        (seconds / DAY, "day")
    } else if seconds >= HOUR {
        (seconds / HOUR, "hour")
    } else if seconds >= MINUTE {
        (seconds / MINUTE, "minute")
    } else {
        return "less than a minute".to_string();
    };
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_age_is_the_biggest_unit_that_fits_rounded_down() {
        for (seconds, text) in [
            (0, "less than a minute"),
            (59, "less than a minute"),
            (60, "1 minute"),
            (119, "1 minute"),
            (120, "2 minutes"),
            (3599, "59 minutes"),
            (3600, "1 hour"),
            (7199, "1 hour"),
            (7200, "2 hours"),
            (86399, "23 hours"),
            (86400, "1 day"),
            (172799, "1 day"),
            (172800, "2 days"),
            (30 * 86400 + 5, "30 days"),
        ] {
            assert_eq!(age_text(seconds), text, "{seconds}");
        }
    }
}
