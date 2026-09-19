//! Property-style coverage for `synvoid-rate-limit` rotation semantics.
//!
//! Deterministic and sleep-free: sweeps window shapes, tick progressions,
//! large jumps, and N/N+1 boundaries. Complements the unit tests in
//! `src/window.rs` and the consumer-mapping tests in `rate_limit_test.rs`.
//!
//! What is pinned here (public contract):
//! - counts at the same tick sum exactly;
//! - exactly N against a limit of N is allowed, N+1 is not;
//! - a jump beyond the whole window clears everything and the window stays usable;
//! - degenerate inputs clamp instead of panicking;
//! - slot mapping is deterministic, in-range, and total for non-zero shard counts.
//!
//! What is NOT pinned: the numeric slot values themselves (implementation detail).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use synvoid_rate_limit::{ip_to_slot, AtomicSlidingWindow, WindowStats};

/// Same-tick inserts sum exactly across a sweep of window shapes.
#[test]
fn same_tick_sum_is_exact_across_shapes() {
    for (secs, buckets) in [(1, 1), (1, 10), (60, 60), (300, 12), (3600, 64)] {
        let window = AtomicSlidingWindow::new(secs, buckets);
        let tick = 12_345u64;
        let n = 250u64;
        for expected in 1..=n {
            assert_eq!(
                window.increment_at(tick),
                expected,
                "shape {secs}s/{buckets}"
            );
        }
        assert_eq!(window.count_at(tick), n);
    }
}

/// N/N+1 boundary holds across a sweep of limits at a fixed tick.
#[test]
fn limit_boundary_holds_across_limits() {
    for limit in [1u64, 2, 5, 10, 100, 1000] {
        let window = AtomicSlidingWindow::new(60, 60);
        let tick = 7_000u64;
        for expected in 1..=limit {
            let count = window.increment_at(tick);
            assert_eq!(count, expected, "limit {limit}");
            assert!(window.stats_at(tick, limit).is_within_limit());
        }
        assert_eq!(window.increment_at(tick), limit + 1);
        let stats = window.stats_at(tick, limit);
        assert!(!stats.is_within_limit());
        assert_eq!(stats.remaining, 0);
        assert_eq!(WindowStats::new(limit, limit).remaining, 0);
        assert!(WindowStats::new(limit, limit).is_within_limit());
    }
}

/// Advancing past the full window clears everything for many shapes/ticks.
#[test]
fn full_window_advance_clears_everything() {
    for (secs, buckets) in [(1, 10), (60, 60), (60, 7), (300, 12)] {
        let window = AtomicSlidingWindow::new(secs, buckets);
        let tick = 1_000u64;
        for _ in 0..13 {
            window.increment_at(tick);
        }
        assert_eq!(window.count_at(tick), 13, "shape {secs}s/{buckets}");
        let window_ms = secs.saturating_mul(1000).max(1);
        // One full window later every bucket is stale.
        assert_eq!(
            window.count_at(tick + window_ms),
            0,
            "shape {secs}s/{buckets}"
        );
        // Usable afterwards at the new baseline.
        assert_eq!(window.increment_at(tick + window_ms), 1);
    }
}

/// Large jumps (near u64::MAX and mid-range) clear stale buckets without wrap-around.
#[test]
fn large_jumps_clear_without_wrap() {
    for (secs, buckets) in [(60, 60), (1, 10), (3600, 64)] {
        let window = AtomicSlidingWindow::new(secs, buckets);
        for _ in 0..9 {
            window.increment_at(5_000);
        }
        assert_eq!(window.count_at(5_000), 9);
        assert_eq!(window.count_at(u64::MAX - 1), 0, "shape {secs}s/{buckets}");
        assert_eq!(window.increment_at(u64::MAX - 1), 1);
        assert_eq!(window.count_at(u64::MAX - 1), 1);
    }
}

/// Monotone tick progression never reports more than the total inserted.
#[test]
fn monotone_progression_never_exceeds_total() {
    let window = AtomicSlidingWindow::new(10, 10);
    let total = 500u64;
    let mut tick = 0u64;
    for i in 0..total {
        tick += 7; // 70ms per event: walks through several buckets
        assert_eq!(window.increment_at(tick), window.count_at(tick));
        assert!(
            window.count_at(tick) <= i + 1,
            "count exceeds inserts at tick {tick}"
        );
    }
}

/// Degenerate and extreme configurations clamp instead of panicking.
#[test]
fn degenerate_and_extreme_configs_clamp() {
    for (secs, buckets) in [(0, 0), (0, 1), (1, 0), (0, 64)] {
        let window = AtomicSlidingWindow::new(secs, buckets);
        assert!(window.bucket_count() >= 1);
        assert!(window.bucket_duration_ms() >= 1);
        assert_eq!(window.increment_at(0), 1);
    }
    // Extreme durations saturate; the bucket count stays caller-sized.
    let window = AtomicSlidingWindow::new(u64::MAX, 8);
    assert_eq!(window.bucket_count(), 8);
    assert!(window.bucket_duration_ms() >= 1);
    window.increment_at(u64::MAX);
    let _ = window.count_at(u64::MAX);
}

/// Slot mapping is deterministic, total, and in-range over a broad sweep.
#[test]
fn slot_mapping_sweep() {
    let v4s: Vec<IpAddr> = (0..256u32)
        .map(|i| IpAddr::V4(Ipv4Addr::from(i.wrapping_mul(16_777_217))))
        .collect();
    let v6s: Vec<IpAddr> = (0..64u32)
        .map(|i| IpAddr::V6(Ipv6Addr::from(i as u128 * 1_000_000_007)))
        .collect();
    for slots in [1usize, 2, 3, 16, 64, 100, 256, 1024, 65_536] {
        for ip in v4s.iter().chain(v6s.iter()) {
            let first = ip_to_slot(*ip, slots).expect("non-zero slots map");
            assert!(first < slots, "slot {first} out of {slots} for {ip}");
            // Deterministic within the version.
            assert_eq!(ip_to_slot(*ip, slots), Some(first));
        }
    }
    let any_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let any_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert_eq!(ip_to_slot(any_v4, 0), None);
    assert_eq!(ip_to_slot(any_v6, 0), None);
}
