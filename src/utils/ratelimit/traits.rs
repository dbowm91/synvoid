use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    Allowed,
    Limited { retry_after_secs: u32 },
}

pub trait IpRateLimiter: Send + Sync {
    fn check(&self, ip: IpAddr) -> RateLimitResult;
}

pub trait KeyedRateLimiter<K: Eq + Hash + Clone>: Send + Sync {
    fn check(&self, key: &K) -> RateLimitResult;
    fn cleanup(&self, max_age: Duration);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitStats {
    pub current_count: u64,
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: Instant,
}

pub trait RateLimitStatsProvider {
    fn get_stats(&self) -> Option<RateLimitStats>;
}
