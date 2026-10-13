//! Wall-clock helpers and the protocol's standard durations (in seconds).

use std::time::{SystemTime, UNIX_EPOCH};

pub const THIRTY_SECONDS: u64 = 30;
pub const FIVE_MINUTES: u64 = 5 * 60;
pub const FIFTEEN_MINUTES: u64 = 15 * 60;
pub const ONE_HOUR: u64 = 60 * 60;
pub const ONE_DAY: u64 = 24 * ONE_HOUR;
pub const SEVEN_DAYS: u64 = 7 * ONE_DAY;
pub const THIRTY_DAYS: u64 = 30 * ONE_DAY;

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    now_ms() / 1000
}

/// Absolute expiry (seconds) `ttl` seconds from now.
pub fn expiry_in(ttl: u64) -> u64 {
    now_secs() + ttl
}

/// Whether an absolute expiry (seconds) has passed.
pub fn is_expired(expiry: u64) -> bool {
    now_secs() >= expiry
}
