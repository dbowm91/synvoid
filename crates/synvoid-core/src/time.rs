/// Returns the current Unix timestamp in seconds.
///
/// This is a pure-function helper that avoids pulling in clock dependencies
/// for simple timestamp needs.
pub fn current_timestamp_secs() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            tracing::warn!("SystemTime before UNIX EPOCH: {}; returning 0", e);
            0
        }
    }
}

/// Returns the current Unix timestamp in milliseconds.
pub fn current_timestamp_millis() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as u64,
        Err(e) => {
            tracing::warn!("SystemTime before UNIX EPOCH: {}; returning 0", e);
            0
        }
    }
}
