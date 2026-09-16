//! Neutral rate-limit admission vocabulary.
//!
//! These contracts are intentionally free of domain concepts: there is no
//! `blackhole`, `threat`, `attack`, `admin`, `upload`, or `mesh` here. Domain
//! crates implement these traits (or adapt [`RateLimitResult`]) and map the
//! outcome onto their own decision types.
//!
//! Moved verbatim from the former root `src/utils/ratelimit` vocabulary so
//! every consumer shares one definition.

use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Policy-neutral admission outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    /// The event is within quota.
    Allowed,
    /// The event exceeds quota; the caller should retry after the given delay.
    Limited { retry_after_secs: u32 },
}

/// Per-IP admission check.
pub trait IpRateLimiter: Send + Sync {
    /// Checks (and usually records) one event for `ip`.
    fn check(&self, ip: IpAddr) -> RateLimitResult;
}

/// Per-key admission check with eviction of stale keys.
pub trait KeyedRateLimiter<K: Eq + Hash + Clone>: Send + Sync {
    /// Checks (and usually records) one event for `key`.
    fn check(&self, key: &K) -> RateLimitResult;
    /// Drops state older than `max_age`.
    fn cleanup(&self, max_age: Duration);
}

/// Policy-neutral quota snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitStats {
    /// Events currently counted against the limit.
    pub current_count: u64,
    /// The configured limit.
    pub limit: u64,
    /// `limit.saturating_sub(current_count)`.
    pub remaining: u64,
    /// When the current window resets (monotonic instant).
    pub reset_at: Instant,
}

/// Exposes a [`RateLimitStats`] snapshot where one is meaningful.
pub trait RateLimitStatsProvider {
    /// Returns the current snapshot, or `None` if the limiter tracks no
    /// single meaningful aggregate (e.g. sharded per-key state).
    fn get_stats(&self) -> Option<RateLimitStats>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Minimal in-test keyed limiter proving the contract shape: boundary at
    /// exactly N/N+1 and deterministic cleanup without sleeps.
    struct TestKeyedLimiter {
        counts: Mutex<HashMap<String, (u64, Instant)>>,
        limit: u64,
    }

    impl KeyedRateLimiter<String> for TestKeyedLimiter {
        fn check(&self, key: &String) -> RateLimitResult {
            let mut counts = self.counts.lock().unwrap();
            let entry = counts.entry(key.clone()).or_insert((0, Instant::now()));
            entry.0 += 1;
            if entry.0 > self.limit {
                RateLimitResult::Limited {
                    retry_after_secs: 1,
                }
            } else {
                RateLimitResult::Allowed
            }
        }

        fn cleanup(&self, _max_age: Duration) {
            self.counts.lock().unwrap().clear();
        }
    }

    #[test]
    fn keyed_contract_enforces_boundary_at_limit_plus_one() {
        let limiter = TestKeyedLimiter {
            counts: Mutex::new(HashMap::new()),
            limit: 2,
        };
        let key = "client".to_string();
        assert_eq!(limiter.check(&key), RateLimitResult::Allowed);
        assert_eq!(limiter.check(&key), RateLimitResult::Allowed);
        assert_eq!(
            limiter.check(&key),
            RateLimitResult::Limited {
                retry_after_secs: 1
            }
        );
        limiter.cleanup(Duration::from_secs(0));
        assert_eq!(limiter.check(&key), RateLimitResult::Allowed);
    }

    #[test]
    fn ip_contract_is_object_safe_behind_arc() {
        struct AllowAll;
        impl IpRateLimiter for AllowAll {
            fn check(&self, _ip: IpAddr) -> RateLimitResult {
                RateLimitResult::Allowed
            }
        }
        let limiter: std::sync::Arc<dyn IpRateLimiter> = std::sync::Arc::new(AllowAll);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(limiter.check(ip), RateLimitResult::Allowed);
    }

    #[test]
    fn stats_remaining_saturates() {
        let stats = RateLimitStats {
            current_count: 9,
            limit: 10,
            remaining: 10u64.saturating_sub(9),
            reset_at: Instant::now() + Duration::from_secs(1),
        };
        assert_eq!(stats.remaining, 1);
    }
}
