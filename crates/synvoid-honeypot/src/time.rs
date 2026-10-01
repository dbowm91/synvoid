//! Small local clock helpers keep this reusable crate independent of
//! application utility crates while retaining safe epoch semantics.
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
