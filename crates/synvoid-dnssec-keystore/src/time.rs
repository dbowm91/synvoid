//! Local wall-clock helper (Phase 34).
//!
//! The keystore previously used `synvoid_core::time::current_timestamp_secs`
//! for key validity and rotation timestamps. That single `u64` primitive was
//! the only `synvoid-core` edge reachable from this crate, so the equivalent
//! `std::time` logic now lives here. The custody boundary no longer depends
//! on the SynVoid application core; timestamps remain plain `u64` Unix
//! seconds with the same fail-to-zero semantics on a pre-epoch clock.

/// Current Unix timestamp in seconds.
///
/// Returns `0` (with a warning) if the system clock reads before the Unix
/// epoch, mirroring the historical `synvoid-core` helper this replaces.
pub(crate) fn now_secs() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            tracing::warn!("SystemTime before UNIX EPOCH: {e}; returning 0");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_is_plausible() {
        // Well past 2026-01-01 (1_769_000_000); guards against a stubbed clock.
        assert!(now_secs() > 1_769_000_000);
    }
}
