use metrics::counter;
use std::sync::atomic::{AtomicU64, Ordering};

pub const MIN_REASONABLE_TIMESTAMP: u64 = 1735689600;
pub const MAX_REASONABLE_TIMESTAMP: u64 = 1893456000;

static TIME_VALIDATION_ERRORS: AtomicU64 = AtomicU64::new(0);

pub fn validate_system_time() {
    let now_unix = crate::utils::safe_unix_timestamp();

    if now_unix < MIN_REASONABLE_TIMESTAMP {
        let offset = MIN_REASONABLE_TIMESTAMP.saturating_sub(now_unix);
        TIME_VALIDATION_ERRORS.fetch_add(1, Ordering::SeqCst);
        counter!("maluwaf.mesh.time_validation.errors", "reason" => "clock_behind").increment(1);
        tracing::error!(
            "System time appears incorrect: {} (Unix timestamp), expected at least {}. \
            Please sync NTP! Clock is off by approximately {} seconds ({} years)",
            now_unix,
            MIN_REASONABLE_TIMESTAMP,
            offset,
            offset / 31536000
        );
    } else if now_unix > MAX_REASONABLE_TIMESTAMP {
        let offset = now_unix.saturating_sub(MAX_REASONABLE_TIMESTAMP);
        TIME_VALIDATION_ERRORS.fetch_add(1, Ordering::SeqCst);
        counter!("maluwaf.mesh.time_validation.errors", "reason" => "clock_ahead").increment(1);
        tracing::error!(
            "System time appears incorrect: {} (Unix timestamp), expected at most {}. \
            Please sync NTP! Clock is off by approximately {} seconds ({} years)",
            now_unix,
            MAX_REASONABLE_TIMESTAMP,
            offset,
            offset / 31536000
        );
    } else {
        counter!("maluwaf.mesh.time_validation.valid").increment(1);
        tracing::info!("System time validated: {} (Unix timestamp)", now_unix);
    }
}

pub fn get_time_validation_error_count() -> u64 {
    TIME_VALIDATION_ERRORS.load(Ordering::SeqCst)
}
