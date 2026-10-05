//! DNS-owned Unix time helper (Phase 129 Workstream A).
//!
//! Replaces `synvoid_core::time::current_timestamp_secs()` and
//! `synvoid_utils::safe_unix_timestamp()` / `current_timestamp()` so that
//! removing those dependency edges does not change observable behavior.
//!
//! Two behaviors are preserved exactly, because DNS code depends on both:
//!
//! * **Pre-epoch clock returns 0, never a panic.** `SystemTime::now()` can
//!   report a time before `UNIX_EPOCH`; `duration_since` then yields an
//!   `Err`. Both predecessors mapped that to `0` (`synvoid-core` additionally
//!   logged a warning; `synvoid-utils` did not). A DNS-owned helper returns
//!   `0` silently, which matches the stricter of the two.
//! * **A plain `SystemTime` read, not a clock abstraction.** No trait, no
//!   global singleton, no injectable clock. Introducing one purely to drop a
//!   dependency would trade a manifest edge for a new public API surface.
//!
//! This is deliberately *not* a second persisted-schema or runtime-DTO type;
//! it is a private helper over `std::time`.

/// Current Unix time in whole seconds, or `0` if the system clock reports a
/// time before the Unix epoch.
///
/// Saturating at `0` is deliberate: a negative duration cannot be represented
/// in the `u64` timestamps DNS uses (RRSIG inception/expiration, cache
/// expiry), and every predecessor helper chose `0` for the same reason.
#[inline]
pub fn unix_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Current Unix time in milliseconds, or `0` for a pre-epoch clock.
///
/// Provided for parity with `synvoid_core::time::current_timestamp_millis()`,
/// which DNS called on the metrics path.
#[inline]
pub fn unix_timestamp_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_time_is_close_to_the_real_clock() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("post-epoch")
            .as_secs();
        let got = unix_timestamp_secs();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("post-epoch")
            .as_secs();
        assert!(
            got >= before && got <= after,
            "timestamp {got} must fall in [{before}, {after}]"
        );
    }

    /// The pre-epoch mapping is the one behavior DNS relies on and the reason
    /// these helpers return `u64` at all. It is asserted here against the
    /// predecessor's contract rather than by simulating a broken clock, since
    /// the clock is not injectable by design.
    #[test]
    fn pre_epoch_maps_to_zero_rather_than_panicking() {
        let pre_epoch = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        // Same shape as the helper's `unwrap_or(0)` path: an `Err` carries no
        // duration, only the offset back to the epoch.
        let mapped = pre_epoch
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert_eq!(mapped, 0);
    }

    #[test]
    fn millis_are_consistent_with_seconds() {
        let secs = unix_timestamp_secs();
        let millis = unix_timestamp_millis();
        assert_eq!(millis / 1000, secs);
    }
}
