pub mod core;
pub mod sliding;

use metrics::{counter, gauge};
use parking_lot::RwLock;
use std::cmp::Reverse;
use std::collections::binary_heap::BinaryHeap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::interval;

use crate::config::defaults::{GlobalRateLimitConfig, IpRateLimitConfig};
use crate::config::RateLimitMemoryConfig;
pub use core::{
    GlobalRateLimitConfig as CoreGlobalConfig, GlobalRateLimiter,
    IpRateLimitConfig as CoreIpConfig, RateLimitDecision, SlottedIpRateLimiter,
};
pub use sliding::{
    GlobalSlidingStats, MultiWindowSlidingLimiter, SlidingDecision, SlidingGlobalDecision,
    SlidingWindowConfig, SlidingWindowLimiter,
};

const DEFAULT_SHARDS: usize = 256;

pub struct RateLimiterState {
    shards: Vec<RateLimiterShard>,
    global_limiter: Arc<GlobalRateLimiter>,
    slotted_ip_limiter: Arc<SlottedIpRateLimiter>,
    semaphore: Arc<Semaphore>,
    config: RateLimitConfigStore,
    memory_config: RateLimitMemoryConfig,
    total_entries: RwLock<usize>,
}

struct RateLimiterShard {
    ip_requests: RwLock<HashMap<IpAddr, IpRateLimitState>>,
    last_cleanup: RwLock<Instant>,
}

#[derive(Default)]
struct IpRateLimitState {
    per_second: RingBuffer<Instant>,
    per_minute: RingBuffer<Instant>,
    per_5min: RingBuffer<Instant>,
    per_10min: RingBuffer<Instant>,
    per_hour: RingBuffer<Instant>,
    per_day: RingBuffer<Instant>,
    last_access: Option<Instant>,
}

impl IpRateLimitState {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            per_second: RingBuffer::with_capacity(10),
            per_minute: RingBuffer::with_capacity(60),
            per_5min: RingBuffer::with_capacity(200),
            per_10min: RingBuffer::with_capacity(350),
            per_hour: RingBuffer::with_capacity(500),
            per_day: RingBuffer::with_capacity(1000),
            last_access: Some(Instant::now()),
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.per_second.is_empty()
            && self.per_minute.is_empty()
            && self.per_5min.is_empty()
            && self.per_10min.is_empty()
            && self.per_hour.is_empty()
            && self.per_day.is_empty()
    }

    fn remove_expired_windows(&mut self, now: Instant) {
        let cutoff_1s = now - Duration::from_secs(1);
        let cutoff_60s = now - Duration::from_secs(60);
        let cutoff_300s = now - Duration::from_secs(300);
        let cutoff_600s = now - Duration::from_secs(600);
        let cutoff_3600s = now - Duration::from_secs(3600);
        let cutoff_86400s = now - Duration::from_secs(86400);

        if !self.per_second.is_empty() {
            self.per_second.remove_older_than(cutoff_1s);
        }
        if !self.per_minute.is_empty() {
            self.per_minute.remove_older_than(cutoff_60s);
        }
        if !self.per_5min.is_empty() {
            self.per_5min.remove_older_than(cutoff_300s);
        }
        if !self.per_10min.is_empty() {
            self.per_10min.remove_older_than(cutoff_600s);
        }
        if !self.per_hour.is_empty() {
            self.per_hour.remove_older_than(cutoff_3600s);
        }
        if !self.per_day.is_empty() {
            self.per_day.remove_older_than(cutoff_86400s);
        }
    }

    fn touch(&mut self) {
        self.last_access = Some(Instant::now());
    }
}

struct RingBuffer<T> {
    data: Vec<T>,
    capacity: usize,
    head: usize,
    len: usize,
}

impl<T> Default for RingBuffer<T> {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            capacity: 0,
            head: 0,
            len: 0,
        }
    }
}

impl<T: Copy> RingBuffer<T> {
    #[allow(dead_code)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            capacity,
            head: 0,
            len: 0,
        }
    }

    #[allow(dead_code)]
    fn push(&mut self, value: T) {
        if self.len < self.capacity {
            self.data.push(value);
            self.len += 1;
        } else if self.capacity > 0 {
            self.data[self.head] = value;
            self.head = (self.head + 1) % self.capacity;
        }
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.len
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    #[allow(dead_code)]
    fn retain<F: FnMut(&T) -> bool>(&mut self, mut f: F) {
        if self.len == 0 {
            return;
        }

        let mut write_idx = 0;

        for i in 0..self.len {
            let read_idx = (self.head + i) % self.capacity;
            if f(&self.data[read_idx]) {
                if write_idx != i {
                    let write_pos = (self.head + write_idx) % self.capacity;
                    self.data[write_pos] = self.data[read_idx];
                }
                write_idx += 1;
            }
        }

        self.len = write_idx;
    }

    /// Remove all entries older than `cutoff`. Exploits the fact that entries
    /// are pushed in chronological order — scans from the oldest entry forward
    /// and stops at the first non-expired entry. O(k) where k = expired count.
    fn remove_older_than(&mut self, cutoff: T)
    where
        T: PartialOrd + Copy,
    {
        if self.len == 0 {
            return;
        }

        let mut expired = 0usize;
        for i in 0..self.len {
            let idx = (self.head + i) % self.capacity;
            if self.data[idx] < cutoff {
                expired += 1;
            } else {
                break;
            }
        }

        if expired > 0 {
            self.head = (self.head + expired) % self.capacity;
            self.len -= expired;
        }
    }
}

#[derive(Clone)]
pub struct RateLimiterManager {
    state: Arc<RateLimiterState>,
}

#[derive(Clone)]
pub struct RateLimitConfigStore {
    pub ip: IpRateLimitConfig,
    pub global: GlobalRateLimitConfig,
    pub cleanup_interval_secs: u64,
}

impl RateLimiterManager {
    pub fn new(
        ip_config: IpRateLimitConfig,
        global_config: GlobalRateLimitConfig,
        cleanup_interval_secs: u64,
        memory_config: RateLimitMemoryConfig,
    ) -> Self {
        let num_shards = if memory_config.num_shards > 0 {
            memory_config.num_shards
        } else {
            DEFAULT_SHARDS
        };

        let mut shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(RateLimiterShard {
                ip_requests: RwLock::new(HashMap::new()),
                last_cleanup: RwLock::new(Instant::now()),
            });
        }

        let core_global_config = CoreGlobalConfig {
            per_second: global_config.per_second,
            per_minute: global_config.per_minute,
            per_5min: global_config.per_5min,
            max_connections: global_config.max_connections,
            blackhole_entry_threshold: 1.0,
            blackhole_exit_threshold: 0.7,
            blackhole_exit_samples: 3,
            blackhole_sample_rate: 1000,
            blackhole_max_backoff_secs: 30,
        };

        let core_ip_config = CoreIpConfig {
            per_second: ip_config.per_second,
            per_minute: ip_config.per_minute,
            per_5min: ip_config.per_5min,
            per_10min: ip_config.per_10min,
            per_hour: ip_config.per_hour,
            per_day: ip_config.per_day,
        };

        let global_limiter = Arc::new(GlobalRateLimiter::new(core_global_config));
        let slotted_ip_limiter = Arc::new(SlottedIpRateLimiter::new(core_ip_config));
        let semaphore = Arc::new(Semaphore::new(global_config.max_connections as usize));

        let state = Arc::new(RateLimiterState {
            shards,
            global_limiter,
            slotted_ip_limiter,
            semaphore,
            config: RateLimitConfigStore {
                ip: ip_config,
                global: global_config,
                cleanup_interval_secs,
            },
            memory_config,
            total_entries: RwLock::new(0),
        });

        if cleanup_interval_secs > 0 {
            let cleanup_state = state.clone();
            tokio::spawn(async move {
                let mut cleanup_timer = interval(Duration::from_secs(cleanup_interval_secs));
                loop {
                    cleanup_timer.tick().await;
                    let now = Instant::now();

                    let mut total = 0usize;

                    for shard in &cleanup_state.shards {
                        {
                            let last = *shard.last_cleanup.read();
                            if now.duration_since(last) < Duration::from_secs(30) {
                                let requests = shard.ip_requests.read();
                                total += requests.len();
                                continue;
                            }
                        }
                        let mut requests = shard.ip_requests.write();
                        requests.retain(|_ip, state| {
                            state.remove_expired_windows(now);

                            if state.is_empty() {
                                false
                            } else {
                                state.touch();
                                true
                            }
                        });
                        total += requests.len();
                        *shard.last_cleanup.write() = now;
                    }

                    cleanup_state.slotted_ip_limiter.decay_all(2);

                    let max_entries = cleanup_state.memory_config.max_ip_entries;
                    if total > max_entries {
                        let to_evict = total - max_entries + (max_entries / 10);
                        Self::evict_lru_entries(&cleanup_state, to_evict);
                    }

                    {
                        let stats = cleanup_state.global_limiter.get_stats();
                        gauge!("maluwaf.ratelimit.global_per_second").set(stats.per_second as f64);
                        gauge!("maluwaf.ratelimit.global_per_minute").set(stats.per_minute as f64);
                        gauge!("maluwaf.ratelimit.blackhole_active")
                            .set(if stats.blackhole_active { 1.0 } else { 0.0 });

                        if stats.blackhole_active {
                            tracing::warn!(
                                "Blackhole mode active - sample rate: 1/{}, consecutive low samples: {}",
                                stats.sample_rate,
                                stats.consecutive_low_samples
                            );
                        }
                    }

                    *cleanup_state.total_entries.write() = total;

                    tracing::debug!(
                        "Rate limit cleanup: {} IPs tracked (max: {})",
                        total,
                        max_entries,
                    );
                }
            });
        }

        RateLimiterManager { state }
    }

    fn evict_lru_entries(state: &Arc<RateLimiterState>, count: usize) {
        // Use a min-heap of size `count` to find the `count` oldest entries
        // without sorting all entries.
        let mut heap: BinaryHeap<Reverse<(Instant, IpAddr)>> = BinaryHeap::with_capacity(count + 1);

        for shard in &state.shards {
            let requests = shard.ip_requests.read();
            for (ip, ip_state) in requests.iter() {
                if let Some(last_access) = ip_state.last_access {
                    if heap.len() < count {
                        heap.push(Reverse((last_access, *ip)));
                    } else if let Some(Reverse((top_time, _))) = heap.peek() {
                        if last_access < *top_time {
                            heap.pop();
                            heap.push(Reverse((last_access, *ip)));
                        }
                    }
                }
            }
        }

        let to_evict: Vec<IpAddr> = heap
            .into_sorted_vec()
            .into_iter()
            .map(|r| (r.0).1)
            .collect();

        let evicted = to_evict.len();
        for ip in to_evict {
            for shard in &state.shards {
                if shard.ip_requests.write().remove(&ip).is_some() {
                    break;
                }
            }
        }

        if evicted > 0 {
            tracing::info!("Evicted {} LRU entries from rate limiter", evicted);
        }
    }

    #[allow(dead_code)]
    fn get_shard(&self, ip: IpAddr) -> &RateLimiterShard {
        let hash = match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let hash = ((octets[0] as u64) * 16777619u64)
                    ^ ((octets[1] as u64) * 2166136261u64)
                    ^ ((octets[2] as u64) ^ ((octets[3] as u64) * 65536u64));
                hash as usize
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                let mut hash = 0u64;
                for (i, &seg) in segments.iter().enumerate() {
                    hash = hash.wrapping_add((seg as u64).wrapping_mul(2166136261u64 >> (i * 5)));
                }
                hash as usize
            }
        };
        let shard_index = hash % self.state.shards.len();
        &self.state.shards[shard_index]
    }

    pub fn check_global(&self) -> RateLimitResult {
        match self.state.global_limiter.check_and_increment() {
            RateLimitDecision::Allowed => RateLimitResult::Allowed,
            RateLimitDecision::Limited { limit_type } => {
                counter!("maluwaf.ratelimit.global_limited").increment(1);
                RateLimitResult::Limited {
                    limit_type: limit_type.to_string(),
                    retry_after_millis: 1000,
                }
            }
            RateLimitDecision::Blackholed => {
                counter!("maluwaf.ratelimit.blackholed").increment(1);
                RateLimitResult::Blackholed
            }
        }
    }

    pub fn is_in_blackhole(&self) -> bool {
        self.state.global_limiter.is_in_blackhole()
    }

    pub async fn check_rate_limit(&self, ip: IpAddr) -> RateLimitResult {
        let decision = self.state.slotted_ip_limiter.check_and_increment(ip);

        match decision {
            RateLimitDecision::Allowed => RateLimitResult::Allowed,
            RateLimitDecision::Limited { limit_type } => {
                counter!("maluwaf.ratelimit.ip_limited").increment(1);
                RateLimitResult::Limited {
                    limit_type: limit_type.to_string(),
                    retry_after_millis: 1000,
                }
            }
            RateLimitDecision::Blackholed => RateLimitResult::Blackholed,
        }
    }

    pub async fn acquire_global_connection(&self) -> Result<GlobalConnectionPermit, ()> {
        match self.state.semaphore.clone().acquire_owned().await {
            Ok(permit) => Ok(GlobalConnectionPermit { _permit: permit }),
            Err(_) => Err(()),
        }
    }

    pub fn get_global_available(&self) -> usize {
        self.state.semaphore.available_permits()
    }

    pub fn get_global_limit(&self) -> u32 {
        self.state.config.global.max_connections
    }

    pub fn get_total_entries(&self) -> usize {
        *self.state.total_entries.read()
    }

    pub fn get_max_entries(&self) -> usize {
        self.state.memory_config.max_ip_entries
    }

    pub fn get_global_stats(&self) -> core::GlobalRateLimitStats {
        self.state.global_limiter.get_stats()
    }
}

pub struct GlobalConnectionPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed,
    Limited {
        limit_type: String,
        retry_after_millis: u64,
    },
    Blackholed,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RingBuffer ─────────────────────────────────────────────────────

    #[test]
    fn ring_buffer_push_within_capacity() {
        let mut rb = RingBuffer::with_capacity(3);
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);

        rb.push(10);
        rb.push(20);
        rb.push(30);

        assert!(!rb.is_empty());
        assert_eq!(rb.len(), 3);
    }

    #[test]
    fn ring_buffer_push_beyond_capacity_wraps() {
        let mut rb = RingBuffer::with_capacity(3);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        // These overwrite positions 0, 1, 2 circularly
        rb.push(4);
        rb.push(5);

        assert_eq!(rb.len(), 3);
    }

    #[test]
    fn ring_buffer_push_zero_capacity_is_noop() {
        let mut rb = RingBuffer::<i32>::with_capacity(0);
        rb.push(1);
        rb.push(2);
        assert_eq!(rb.len(), 0);
        assert!(rb.is_empty());
    }

    #[test]
    fn ring_buffer_retain_keeps_matching() {
        let mut rb = RingBuffer::with_capacity(5);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        rb.push(4);

        rb.retain(|&v| v % 2 == 0);
        assert_eq!(rb.len(), 2);
    }

    #[test]
    fn ring_buffer_retain_empty_buffer() {
        let mut rb = RingBuffer::<i32>::with_capacity(3);
        rb.retain(|_| false);
        assert_eq!(rb.len(), 0);
        assert!(rb.is_empty());
    }

    #[test]
    fn ring_buffer_retain_remove_all() {
        let mut rb = RingBuffer::with_capacity(3);
        rb.push(1);
        rb.push(2);
        rb.push(3);

        rb.retain(|_| false);
        assert_eq!(rb.len(), 0);
        assert!(rb.is_empty());
    }

    #[test]
    fn ring_buffer_retain_keep_all() {
        let mut rb = RingBuffer::with_capacity(3);
        rb.push(1);
        rb.push(2);
        rb.push(3);

        rb.retain(|_| true);
        assert_eq!(rb.len(), 3);
    }

    // ── IpRateLimitState ───────────────────────────────────────────────

    #[test]
    fn ip_rate_limit_state_new_is_not_empty() {
        // After new(), per_second etc. have capacity 0 so len==0, but we
        // need to verify the is_empty() logic.
        let state = IpRateLimitState::new();
        assert!(state.is_empty());
    }

    #[test]
    fn ip_rate_limit_state_empty_after_push_and_retain() {
        let mut state = IpRateLimitState::new();
        state.per_second.push(Instant::now());
        assert!(!state.is_empty());

        state.per_second.retain(|_| false);
        assert!(state.is_empty());
    }
}
