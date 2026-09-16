//! Integration coverage for `synvoid-rate-limit` as consumed by domains.
//!
//! These tests exercise the crate the way WAF and mesh policy code does:
//! explicit deterministic ticks, monotonic clocks, quota snapshots, and the
//! neutral admission contracts — with no wall-clock sleeps.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::thread;
use synvoid_rate_limit::{
    ip_to_slot, AtomicSlidingWindow, RateLimitResult, RateLimitStats, RateLimitStatsProvider,
    WindowClock,
};

/// Mirrors the WAF pattern: several windows with different spans fed from one
/// monotonic baseline, mapped onto an allow/limit verdict by the caller.
#[test]
fn multi_window_policy_mapping_with_one_clock() {
    let clock = WindowClock::new();
    let second = AtomicSlidingWindow::new(1, 10);
    let minute = AtomicSlidingWindow::new(60, 60);

    for _ in 0..5 {
        second.increment_now(&clock);
        minute.increment_now(&clock);
    }

    let verdict = |count: u64, limit: u64| {
        if count > limit {
            RateLimitResult::Limited {
                retry_after_secs: 1,
            }
        } else {
            RateLimitResult::Allowed
        }
    };
    assert_eq!(
        verdict(second.count_now(&clock), 10),
        RateLimitResult::Allowed
    );
    assert_eq!(
        verdict(second.count_now(&clock), 3),
        RateLimitResult::Limited {
            retry_after_secs: 1
        }
    );
    assert_eq!(
        verdict(minute.count_now(&clock), 100),
        RateLimitResult::Allowed
    );
}

/// Mirrors the mesh pattern: a per-peer limiter with separate windows whose
/// check/record split preserves configured limits after migration.
#[test]
fn mesh_style_check_then_record_enforces_configured_limits() {
    let clock = WindowClock::new();
    let per_second = AtomicSlidingWindow::new(1, 10);
    let max_per_second = 2u64;

    let check = || per_second.count_now(&clock) < max_per_second;
    let record = || {
        per_second.increment_now(&clock);
    };

    assert!(check());
    record();
    assert!(check());
    record();
    assert!(!check());
}

/// Stats providers stay policy-neutral: remaining saturates, reset is monotonic.
#[test]
fn stats_provider_snapshot_is_policy_neutral() {
    struct Snapshot {
        count: u64,
        limit: u64,
    }
    impl RateLimitStatsProvider for Snapshot {
        fn get_stats(&self) -> Option<RateLimitStats> {
            Some(RateLimitStats {
                current_count: self.count,
                limit: self.limit,
                remaining: self.limit.saturating_sub(self.count),
                reset_at: std::time::Instant::now() + std::time::Duration::from_secs(1),
            })
        }
    }

    let stats = Snapshot {
        count: 7,
        limit: 10,
    }
    .get_stats()
    .unwrap();
    assert_eq!(stats.remaining, 3);
    let over = Snapshot {
        count: 11,
        limit: 10,
    }
    .get_stats()
    .unwrap();
    assert_eq!(over.remaining, 0);
}

/// Two subsystems sharing one primitive must observe identical rotation.
#[test]
fn shared_primitive_rotation_is_consistent_across_consumers() {
    let a = Arc::new(AtomicSlidingWindow::new(60, 60));
    let b = Arc::clone(&a);
    let tick = 5_000u64;

    let writer = thread::spawn(move || {
        for _ in 0..100 {
            b.increment_at(tick);
        }
    });
    for _ in 0..100 {
        a.increment_at(tick);
    }
    writer.join().unwrap();
    assert_eq!(a.count_at(tick), 200);
    // One full window later both consumers observe the same expiry.
    assert_eq!(a.count_at(tick + 60_000), 0);
}

/// Slot helper behaves identically for the shard counts WAF/mesh use.
#[test]
fn slot_helper_covers_waf_and_mesh_shard_counts() {
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    for slots in [16usize, 256, 65_536] {
        let slot = ip_to_slot(ip, slots).unwrap();
        assert!(slot < slots);
    }
    assert_eq!(ip_to_slot(ip, 0), None);
}
