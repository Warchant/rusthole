//! Time rules of the statistics store: flush, retention, rate-limited warnings and the UTC
//! offset of hour histograms. All functions are pure. The shell gives `now`.

use super::{HOUR_SECONDS, hour_of};

/// The shortest time between two early flushes (the key bound is near), in milliseconds.
/// It stops a flush loop when the database fails.
pub const EARLY_FLUSH_MIN_GAP_MS: u64 = 5_000;

/// The largest UTC offset for hour histograms, in minutes (docs/API.md section 1.4).
pub const MAX_UTC_OFFSET_MINUTES: i32 = 840;

/// Decides if the store must flush now.
///
/// - `interval_ms`: the flush interval. 0 means RAM only: never flush.
/// - `now_ms` and `last_attempt_ms`: monotonic milliseconds. A failed flush is an attempt
///   too, so the store tries again after the interval (or after the early-flush gap).
/// - `near_full`: the RAM aggregate is near its key bound.
pub fn flush_due(interval_ms: u64, now_ms: u64, last_attempt_ms: u64, near_full: bool) -> bool {
    if interval_ms == 0 {
        return false;
    }
    let elapsed = now_ms.saturating_sub(last_attempt_ms);
    elapsed >= interval_ms || (near_full && elapsed >= EARLY_FLUSH_MIN_GAP_MS)
}

/// The UTC day of a Unix time.
pub fn day_of(now: i64) -> i64 {
    now.div_euclid(24 * HOUR_SECONDS)
}

/// True when the retention must run: once for each UTC day. `last_day` is the day of the
/// last run, or `None` when it never ran.
pub fn retention_due(last_day: Option<i64>, now: i64) -> bool {
    last_day != Some(day_of(now))
}

/// The first hour bucket to keep. The retention deletes all hours before it.
///
/// The store keeps `retention_days` whole days before the current hour. A value of 0 is
/// handled as 1 day.
pub fn retention_cutoff_hour(now: i64, retention_days: u32) -> i64 {
    let hours = i64::from(retention_days.max(1)).saturating_mul(24);
    hour_of(now).saturating_sub(hours)
}

/// True when a rate-limited warning can be logged again. Times are monotonic milliseconds.
/// `last_ms` is `None` before the first warning.
pub fn warn_due(last_ms: Option<u64>, now_ms: u64, interval_ms: u64) -> bool {
    match last_ms {
        None => true,
        Some(last) => now_ms.saturating_sub(last) >= interval_ms,
    }
}

/// The UTC offset that the hour histograms really use, in minutes.
///
/// The offset is clamped to `-840..=840` and rounded down to a whole hour (docs/API.md
/// section 1.4): +330 gives +300, and -210 gives -240.
pub fn effective_utc_offset(utc_offset_minutes: i32) -> i32 {
    let clamped = utc_offset_minutes.clamp(-MAX_UTC_OFFSET_MINUTES, MAX_UTC_OFFSET_MINUTES);
    clamped.div_euclid(60) * 60
}

/// The hour of day (0 to 23) of an hour bucket, with the offset in whole hours.
pub fn hour_of_day(hour_utc: i64, effective_offset_minutes: i32) -> usize {
    let local = hour_utc.saturating_add(i64::from(effective_offset_minutes.div_euclid(60)));
    // `rem_euclid(24)` is in 0..24, so the conversion cannot fail.
    usize::try_from(local.rem_euclid(24)).unwrap_or(0)
}
