//! Unix timestamp helper with no `synvoid-utils` dependency.
//!
//! `synvoid-mesh-protocol` must not depend on `synvoid-utils` unless a truly
//! low-level type is required. Time is obtained directly from `SystemTime`
//! so the crate stays dependency-minimal and testable with no network access.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix timestamp in seconds, saturating to 0 on clock error.
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
