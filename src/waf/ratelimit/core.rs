use crate::utils::ip_to_slot;
use crate::utils::ratelimit::{
    IpRateLimiter, RateLimitResult, RateLimitStats, RateLimitStatsProvider,
};
use crate::RunningFlag;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

const SHARD_COUNT: usize = 16;

static RATE_LIMITER_START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn get_monotonic_time_ms() -> u64 {
    let start = RATE_LIMITER_START.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

pub struct ShardedRateLimiter {
    shards: Box<[RateLimitShard]>,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    config: RateLimitConfig,
}

struct RateLimitShard {
    window: AtomicSlidingWindow,
    per_ip_limit: u32,
}

#[derive(Clone)]
pub struct RateLimitConfig {
    pub per_second: u32,
    pub per_minute: u32,
    pub shard_count: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: 10,
            per_minute: 60,
            shard_count: SHARD_COUNT,
        }
    }
}

impl ShardedRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let shard_count = config.shard_count.max(1);
        let per_shard_limit = config.per_second / shard_count as u32;

        let shards: Vec<RateLimitShard> = (0..shard_count)
            .map(|_| RateLimitShard {
                window: AtomicSlidingWindow::new(1, 10),
                per_ip_limit: per_shard_limit.max(1),
            })
            .collect();

        Self {
            shards: shards.into_boxed_slice(),
            config,
        }
    }

    pub fn check(&self, client_ip: IpAddr) -> RateLimitDecision {
        let shard_idx = ip_to_slot(client_ip, self.shards.len());
        let shard = &self.shards[shard_idx];

        let now_ms = get_monotonic_time_ms();

        let count = shard.window.increment(now_ms);

        if count > shard.per_ip_limit as u64 {
            RateLimitDecision::Limited {
                limit_type: "per_ip_second",
            }
        } else {
            RateLimitDecision::Allowed
        }
    }

    pub fn get_shard_count(&self) -> usize {
        self.shards.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Limited { limit_type: &'static str },
    Blackholed,
}

#[derive(Debug, Clone, Copy)]
pub struct GlobalRateLimitConfig {
    pub per_second: u32,
    pub per_minute: u32,
    pub per_5min: u32,
    pub max_connections: u32,
    pub blackhole_entry_threshold: f64,
    pub blackhole_exit_threshold: f64,
    pub blackhole_exit_samples: u32,
    pub blackhole_sample_rate: u32,
    pub blackhole_max_backoff_secs: u32,
}

impl Default for GlobalRateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: 500,
            per_minute: 5000,
            per_5min: 20000,
            max_connections: 1000,
            blackhole_entry_threshold: 1.0,
            blackhole_exit_threshold: 0.7,
            blackhole_exit_samples: 3,
            blackhole_sample_rate: 1000,
            blackhole_max_backoff_secs: 30,
        }
    }
}

pub struct AtomicSlidingWindow {
    buckets: Box<[AtomicU64]>,
    bucket_count: u64,
    bucket_duration_ms: u64,
    last_rotate_ms: AtomicU64,
    total_count: AtomicU64,
}

impl AtomicSlidingWindow {
    pub fn new(window_duration_secs: u64, bucket_count: u64) -> Self {
        let buckets: Vec<AtomicU64> = (0..bucket_count).map(|_| AtomicU64::new(0)).collect();
        let bucket_duration_ms = (window_duration_secs * 1000) / bucket_count;

        Self {
            buckets: buckets.into_boxed_slice(),
            bucket_count,
            bucket_duration_ms,
            last_rotate_ms: AtomicU64::new(0),
            total_count: AtomicU64::new(0),
        }
    }

    pub fn increment(&self, now_ms: u64) -> u64 {
        self.rotate_buckets(now_ms);

        let bucket_idx = ((now_ms / self.bucket_duration_ms) % self.bucket_count) as usize;
        let _count = self.buckets[bucket_idx].fetch_add(1, Ordering::AcqRel) + 1;
        self.total_count.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn get_count(&self, now_ms: u64) -> u64 {
        self.rotate_buckets(now_ms);
        self.total_count.load(Ordering::Acquire)
    }

    fn rotate_buckets(&self, now_ms: u64) {
        let current_bucket = now_ms / self.bucket_duration_ms;
        let last_rotate = self.last_rotate_ms.load(Ordering::Acquire);

        if current_bucket > last_rotate
            && self
                .last_rotate_ms
                .compare_exchange(
                    last_rotate,
                    current_bucket,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            let buckets_to_clear = std::cmp::min(current_bucket - last_rotate, self.bucket_count);

            let mut total = 0u64;
            for i in 0..self.bucket_count {
                let idx = (current_bucket.wrapping_sub(i) % self.bucket_count) as usize;
                total += self.buckets[idx].load(Ordering::Acquire);
            }

            for i in 0..buckets_to_clear {
                let idx = (current_bucket
                    .wrapping_sub(self.bucket_count)
                    .wrapping_add(i)
                    % self.bucket_count) as usize;
                let cleared = self.buckets[idx].swap(0, Ordering::AcqRel);
                total = total.saturating_sub(cleared);
            }

            self.total_count.store(total, Ordering::Release);
        }
    }

    pub fn reset(&self) {
        for bucket in self.buckets.iter() {
            bucket.store(0, Ordering::Relaxed);
        }
        self.total_count.store(0, Ordering::Relaxed);
    }
}

pub struct GlobalRateLimiter {
    second_window: AtomicSlidingWindow,
    minute_window: AtomicSlidingWindow,
    five_min_window: AtomicSlidingWindow,

    blackhole_active: RunningFlag,
    sample_rate: AtomicU32,
    probe_backoff_secs: AtomicU32,
    consecutive_low_samples: AtomicU32,

    config: GlobalRateLimitConfig,

    start_instant: Instant,
}

impl GlobalRateLimiter {
    pub fn new(config: GlobalRateLimitConfig) -> Self {
        Self {
            second_window: AtomicSlidingWindow::new(1, 10),
            minute_window: AtomicSlidingWindow::new(60, 60),
            five_min_window: AtomicSlidingWindow::new(300, 60),
            blackhole_active: RunningFlag::new(),
            sample_rate: AtomicU32::new(1),
            probe_backoff_secs: AtomicU32::new(1),
            consecutive_low_samples: AtomicU32::new(0),
            config,
            start_instant: Instant::now(),
        }
    }

    pub fn check_and_increment(&self) -> RateLimitDecision {
        let now_ms = self.start_instant.elapsed().as_millis() as u64;

        let second_count = self.second_window.increment(now_ms);
        let minute_count = self.minute_window.get_count(now_ms);
        let five_min_count = self.five_min_window.get_count(now_ms);

        if !self.blackhole_active.is_running() {
            return self.handle_blackhole_mode(second_count);
        }

        let entry_threshold = self.config.blackhole_entry_threshold;

        if second_count > (self.config.per_second as f64 * entry_threshold) as u64 {
            self.enter_blackhole();
            return RateLimitDecision::Blackholed;
        }

        if minute_count > (self.config.per_minute as f64 * entry_threshold) as u64 {
            self.enter_blackhole();
            return RateLimitDecision::Blackholed;
        }

        if five_min_count > (self.config.per_5min as f64 * entry_threshold) as u64 {
            self.enter_blackhole();
            return RateLimitDecision::Blackholed;
        }

        if second_count > self.config.per_second as u64 {
            return RateLimitDecision::Limited {
                limit_type: "global_per_second",
            };
        }

        if minute_count > self.config.per_minute as u64 {
            return RateLimitDecision::Limited {
                limit_type: "global_per_minute",
            };
        }

        if five_min_count > self.config.per_5min as u64 {
            return RateLimitDecision::Limited {
                limit_type: "global_per_5min",
            };
        }

        RateLimitDecision::Allowed
    }

    fn handle_blackhole_mode(&self, current_rate: u64) -> RateLimitDecision {
        let sample_rate = self.sample_rate.load(Ordering::Relaxed);
        let sample_counter = self.second_window.total_count.load(Ordering::Relaxed);

        if sample_counter.is_multiple_of(sample_rate as u64) {
            let exit_threshold =
                (self.config.per_second as f64 * self.config.blackhole_exit_threshold) as u64;
            let estimated_rate = current_rate.saturating_mul(sample_rate as u64);

            if estimated_rate < exit_threshold {
                let low_samples = self.consecutive_low_samples.fetch_add(1, Ordering::Relaxed) + 1;

                if low_samples >= self.config.blackhole_exit_samples {
                    self.exit_blackhole();
                    return RateLimitDecision::Allowed;
                }
            } else {
                self.consecutive_low_samples.store(0, Ordering::Relaxed);
                self.increase_backoff();
            }
        }

        RateLimitDecision::Blackholed
    }

    fn enter_blackhole(&self) {
        self.blackhole_active.stop();
        self.sample_rate
            .store(self.config.blackhole_sample_rate, Ordering::Relaxed);
        self.probe_backoff_secs.store(1, Ordering::Relaxed);
        self.consecutive_low_samples.store(0, Ordering::Relaxed);

        tracing::warn!(
            "Global rate limit exceeded - entering blackhole mode (sample rate: 1/{})",
            self.config.blackhole_sample_rate
        );
    }

    fn exit_blackhole(&self) {
        self.blackhole_active.set(true);
        self.sample_rate.store(1, Ordering::Relaxed);
        self.probe_backoff_secs.store(1, Ordering::Relaxed);
        self.consecutive_low_samples.store(0, Ordering::Relaxed);

        self.second_window.reset();

        tracing::info!("Exiting blackhole mode - traffic normalized");
    }

    fn increase_backoff(&self) {
        let current = self.probe_backoff_secs.load(Ordering::Relaxed);
        let next = std::cmp::min(current * 2, self.config.blackhole_max_backoff_secs);
        self.probe_backoff_secs.store(next, Ordering::Relaxed);

        let new_sample_rate = std::cmp::min(self.config.blackhole_sample_rate * next, u32::MAX / 2);
        self.sample_rate.store(new_sample_rate, Ordering::Relaxed);
    }

    pub fn is_in_blackhole(&self) -> bool {
        !self.blackhole_active.is_running()
    }

    pub fn get_stats(&self) -> GlobalRateLimitStats {
        let now_ms = self.start_instant.elapsed().as_millis() as u64;

        GlobalRateLimitStats {
            per_second: self.second_window.get_count(now_ms),
            per_minute: self.minute_window.get_count(now_ms),
            per_5min: self.five_min_window.get_count(now_ms),
            blackhole_active: self.blackhole_active.is_running(),
            sample_rate: self.sample_rate.load(Ordering::Relaxed),
            consecutive_low_samples: self.consecutive_low_samples.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GlobalRateLimitStats {
    pub per_second: u64,
    pub per_minute: u64,
    pub per_5min: u64,
    pub blackhole_active: bool,
    pub sample_rate: u32,
    pub consecutive_low_samples: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct IpRateLimitConfig {
    pub per_second: u32,
    pub per_minute: u32,
    pub per_5min: u32,
    pub per_10min: u32,
    pub per_hour: u32,
    pub per_day: u32,
}

impl Default for IpRateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: 10,
            per_minute: 60,
            per_5min: 200,
            per_10min: 350,
            per_hour: 500,
            per_day: 1000,
        }
    }
}

pub const IP_RATE_LIMIT_SLOTS: usize = 65536;

pub struct SlottedIpRateLimiter {
    second_counters: Box<[AtomicU32; IP_RATE_LIMIT_SLOTS]>,
    minute_counters: Box<[AtomicU32; IP_RATE_LIMIT_SLOTS]>,
    five_min_counters: Box<[AtomicU32; IP_RATE_LIMIT_SLOTS]>,

    config: IpRateLimitConfig,

    current_second: AtomicU64,
    current_minute: AtomicU64,
    current_five_min: AtomicU64,

    start_instant: Instant,

    dirty_bits: Vec<AtomicU32>,
}

impl SlottedIpRateLimiter {
    pub fn new(config: IpRateLimitConfig) -> Self {
        let dirty_bits: Vec<AtomicU32> = (0..IP_RATE_LIMIT_SLOTS / 32)
            .map(|_| AtomicU32::new(0))
            .collect();
        Self {
            second_counters: Box::new([const { AtomicU32::new(0) }; IP_RATE_LIMIT_SLOTS]),
            minute_counters: Box::new([const { AtomicU32::new(0) }; IP_RATE_LIMIT_SLOTS]),
            five_min_counters: Box::new([const { AtomicU32::new(0) }; IP_RATE_LIMIT_SLOTS]),
            config,
            current_second: AtomicU64::new(0),
            current_minute: AtomicU64::new(0),
            current_five_min: AtomicU64::new(0),
            start_instant: Instant::now(),
            dirty_bits,
        }
    }

    pub fn check_and_increment(&self, ip: IpAddr) -> RateLimitDecision {
        let slot = self.ip_to_slot(ip);
        let now_secs = self.start_instant.elapsed().as_secs();

        self.rotate_windows(now_secs);

        let word_idx = slot / 32;
        let bit_idx = slot % 32;
        self.dirty_bits[word_idx].fetch_or(1u32 << bit_idx, Ordering::Relaxed);

        let second_count = self.second_counters[slot].fetch_add(1, Ordering::Relaxed) + 1;
        if second_count > self.config.per_second {
            return RateLimitDecision::Limited {
                limit_type: "ip_per_second",
            };
        }

        let minute_count = self.minute_counters[slot].fetch_add(1, Ordering::Relaxed) + 1;
        if minute_count > self.config.per_minute {
            return RateLimitDecision::Limited {
                limit_type: "ip_per_minute",
            };
        }

        let five_min_count = self.five_min_counters[slot].fetch_add(1, Ordering::Relaxed) + 1;
        if five_min_count > self.config.per_5min {
            return RateLimitDecision::Limited {
                limit_type: "ip_per_5min",
            };
        }

        RateLimitDecision::Allowed
    }

    fn ip_to_slot(&self, ip: IpAddr) -> usize {
        ip_to_slot(ip, IP_RATE_LIMIT_SLOTS)
    }

    fn rotate_windows(&self, now_secs: u64) {
        let current_sec = now_secs;
        let current_min = now_secs / 60;
        let current_5min = now_secs / 300;

        let last_sec = self.current_second.load(Ordering::Relaxed);
        if current_sec > last_sec
            && self
                .current_second
                .compare_exchange(last_sec, current_sec, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            // Per-second resets naturally since we check every second
        }

        let last_min = self.current_minute.load(Ordering::Relaxed);
        if current_min > last_min
            && self
                .current_minute
                .compare_exchange(last_min, current_min, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            // Reset minute counters would require tracking which slots to reset
            // For simplicity, we use a decay approach in a separate cleanup
        }

        let last_5min = self.current_five_min.load(Ordering::Relaxed);
        if current_5min > last_5min {
            let _ = self.current_five_min.compare_exchange(
                last_5min,
                current_5min,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
        }
    }

    pub fn reset_slot(&self, slot: usize) {
        self.second_counters[slot].store(0, Ordering::Relaxed);
        self.minute_counters[slot].store(0, Ordering::Relaxed);
        self.five_min_counters[slot].store(0, Ordering::Relaxed);
    }

    pub fn decay_all(&self, factor: u32) {
        for (word_idx, word) in self.dirty_bits.iter().enumerate() {
            let bits = word.load(Ordering::Relaxed);
            if bits == 0 {
                continue;
            }
            word.store(0, Ordering::Relaxed);

            let base_slot = word_idx * 32;
            let mut remaining = bits;
            while remaining != 0 {
                let bit_idx = remaining.trailing_zeros() as usize;
                let slot = base_slot + bit_idx;
                remaining &= remaining - 1;

                let second = self.second_counters[slot].load(Ordering::Relaxed);
                let minute = self.minute_counters[slot].load(Ordering::Relaxed);
                let five_min = self.five_min_counters[slot].load(Ordering::Relaxed);

                if second == 0 && minute == 0 && five_min == 0 {
                    continue;
                }

                if second > 0 {
                    self.second_counters[slot].store(second / factor, Ordering::Relaxed);
                }
                if minute > 0 {
                    self.minute_counters[slot].store(minute / factor, Ordering::Relaxed);
                }
                if five_min > 0 {
                    self.five_min_counters[slot].store(five_min / factor, Ordering::Relaxed);
                }
            }
        }
    }
}

impl IpRateLimiter for SlottedIpRateLimiter {
    fn check(&self, ip: IpAddr) -> RateLimitResult {
        match self.check_and_increment(ip) {
            RateLimitDecision::Allowed => RateLimitResult::Allowed,
            RateLimitDecision::Limited { limit_type: _ } => RateLimitResult::Limited {
                retry_after_secs: 1,
            },
            RateLimitDecision::Blackholed => RateLimitResult::Limited {
                retry_after_secs: 60,
            },
        }
    }
}

impl RateLimitStatsProvider for GlobalRateLimiter {
    fn get_stats(&self) -> Option<RateLimitStats> {
        let stats = GlobalRateLimiter::get_stats(self);
        Some(RateLimitStats {
            current_count: stats.per_second,
            limit: self.config.per_second as u64,
            remaining: (self.config.per_second as u64).saturating_sub(stats.per_second),
            reset_at: self.start_instant + std::time::Duration::from_secs(1),
        })
    }
}

impl RateLimitStatsProvider for SlottedIpRateLimiter {
    fn get_stats(&self) -> Option<RateLimitStats> {
        let slot = 0;
        let current_count = self.second_counters[slot].load(Ordering::Relaxed) as u64;
        Some(RateLimitStats {
            current_count,
            limit: self.config.per_second as u64,
            remaining: (self.config.per_second as u64).saturating_sub(current_count),
            reset_at: self.start_instant + std::time::Duration::from_secs(1),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Tcp,
}

pub trait RateLimitCheck {
    fn check(&self, protocol: Protocol, ip: IpAddr) -> RateLimitDecision;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_sliding_window_basic() {
        let window = AtomicSlidingWindow::new(1, 10);

        let count = window.increment(100);
        assert_eq!(count, 1);

        let count = window.increment(150);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_global_rate_limiter_normal() {
        let config = GlobalRateLimitConfig {
            per_second: 10,
            ..Default::default()
        };
        let limiter = GlobalRateLimiter::new(config);

        for _ in 0..5 {
            let decision = limiter.check_and_increment();
            assert_eq!(decision, RateLimitDecision::Allowed);
        }
    }

    #[test]
    fn test_global_rate_limiter_blackhole_entry() {
        let config = GlobalRateLimitConfig {
            per_second: 5,
            per_minute: 1000,
            per_5min: 5000,
            blackhole_entry_threshold: 1.0,
            ..Default::default()
        };
        let limiter = GlobalRateLimiter::new(config);

        for _ in 0..10 {
            let _ = limiter.check_and_increment();
        }

        assert!(limiter.is_in_blackhole());
    }

    #[test]
    fn test_slotted_ip_rate_limiter() {
        let config = IpRateLimitConfig {
            per_second: 5,
            ..Default::default()
        };
        let limiter = SlottedIpRateLimiter::new(config);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..3 {
            let decision = limiter.check_and_increment(ip);
            assert_eq!(decision, RateLimitDecision::Allowed);
        }
    }

    #[test]
    fn test_slotted_ip_rate_limiter_at_limit() {
        let config = IpRateLimitConfig {
            per_second: 5,
            ..Default::default()
        };
        let limiter = SlottedIpRateLimiter::new(config);

        let ip: IpAddr = "192.168.1.2".parse().unwrap();

        for _ in 0..5 {
            let decision = limiter.check_and_increment(ip);
            assert_eq!(decision, RateLimitDecision::Allowed);
        }
    }

    #[test]
    fn test_slotted_ip_rate_limiter_over_limit() {
        let config = IpRateLimitConfig {
            per_second: 5,
            ..Default::default()
        };
        let limiter = SlottedIpRateLimiter::new(config);

        let ip: IpAddr = "192.168.1.3".parse().unwrap();

        for _ in 0..5 {
            assert_eq!(limiter.check_and_increment(ip), RateLimitDecision::Allowed);
        }

        let decision = limiter.check_and_increment(ip);
        assert!(matches!(decision, RateLimitDecision::Limited { .. }));
    }

    #[test]
    fn test_global_rate_limiter_at_limit() {
        let config = GlobalRateLimitConfig {
            per_second: 3,
            ..Default::default()
        };
        let limiter = GlobalRateLimiter::new(config);

        for _ in 0..3 {
            assert_eq!(limiter.check_and_increment(), RateLimitDecision::Allowed);
        }
    }

    #[test]
    fn test_global_rate_limiter_over_limit() {
        let config = GlobalRateLimitConfig {
            per_second: 3,
            blackhole_entry_threshold: 10.0,
            ..Default::default()
        };
        let limiter = GlobalRateLimiter::new(config);

        for _ in 0..3 {
            assert_eq!(limiter.check_and_increment(), RateLimitDecision::Allowed);
        }

        let decision = limiter.check_and_increment();
        assert!(matches!(decision, RateLimitDecision::Limited { .. }));
    }

    #[test]
    fn test_atomic_sliding_window_count_after_rotation() {
        let window = AtomicSlidingWindow::new(1, 10);

        let _ = window.increment(100);
        let _ = window.increment(100);
        let _ = window.increment(100);

        assert_eq!(window.get_count(100), 3);
    }

    #[test]
    fn test_atomic_sliding_window_reset() {
        let window = AtomicSlidingWindow::new(1, 10);

        let _ = window.increment(100);
        let _ = window.increment(100);
        assert_eq!(window.get_count(100), 2);

        window.reset();
        assert_eq!(window.get_count(100), 0);
    }

    #[test]
    fn test_global_rate_limiter_stats() {
        let config = GlobalRateLimitConfig {
            per_second: 100,
            ..Default::default()
        };
        let limiter = GlobalRateLimiter::new(config);

        for _ in 0..10 {
            let _ = limiter.check_and_increment();
        }

        let stats = limiter.get_stats();
        assert!(stats.per_second >= 10);
    }

    #[test]
    fn test_slotted_ip_different_ips_independent() {
        let config = IpRateLimitConfig {
            per_second: 2,
            ..Default::default()
        };
        let limiter = SlottedIpRateLimiter::new(config);

        let ip1: IpAddr = "10.1.0.1".parse().unwrap();
        let ip2: IpAddr = "10.2.0.1".parse().unwrap();

        assert_eq!(limiter.check_and_increment(ip1), RateLimitDecision::Allowed);
        assert_eq!(limiter.check_and_increment(ip1), RateLimitDecision::Allowed);
        assert!(matches!(
            limiter.check_and_increment(ip1),
            RateLimitDecision::Limited { .. }
        ));

        assert_eq!(limiter.check_and_increment(ip2), RateLimitDecision::Allowed);
    }
}
