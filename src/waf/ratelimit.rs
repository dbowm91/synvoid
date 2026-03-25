pub mod core;
pub mod sliding;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::interval;
use parking_lot::RwLock;
use metrics::{counter, gauge};

use crate::config::defaults::{IpRateLimitConfig, GlobalRateLimitConfig};
use crate::config::RateLimitMemoryConfig;
pub use core::{GlobalRateLimiter, GlobalRateLimitConfig as CoreGlobalConfig, SlottedIpRateLimiter, IpRateLimitConfig as CoreIpConfig, RateLimitDecision};
pub use sliding::{
    SlidingWindowConfig, SlidingWindowLimiter, SlidingDecision,
    MultiWindowSlidingLimiter, SlidingGlobalDecision, GlobalSlidingStats,
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
    fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            capacity,
            head: 0,
            len: 0,
        }
    }

    fn push(&mut self, value: T) {
        if self.len < self.capacity {
            self.data.push(value);
            self.len += 1;
        } else if self.capacity > 0 {
            self.data[self.head] = value;
            self.head = (self.head + 1) % self.capacity;
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
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
                        let mut requests = shard.ip_requests.write();
                        requests.retain(|_ip, state| {
                            state.per_second.retain(|t| now.duration_since(*t) < Duration::from_secs(1));
                            state.per_minute.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
                            state.per_5min.retain(|t| now.duration_since(*t) < Duration::from_secs(300));
                            state.per_10min.retain(|t| now.duration_since(*t) < Duration::from_secs(600));
                            state.per_hour.retain(|t| now.duration_since(*t) < Duration::from_secs(3600));
                            state.per_day.retain(|t| now.duration_since(*t) < Duration::from_secs(86400));
                            
                            if state.is_empty() {
                                false
                            } else {
                                state.touch();
                                true
                            }
                        });
                        total += requests.len();
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
                        gauge!("maluwaf.ratelimit.blackhole_active").set(if stats.blackhole_active { 1.0 } else { 0.0 });
                        
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
        let mut all_entries: Vec<(IpAddr, Instant)> = Vec::new();
        
        for shard in &state.shards {
            let requests = shard.ip_requests.read();
            for (ip, ip_state) in requests.iter() {
                if let Some(last_access) = ip_state.last_access {
                    all_entries.push((*ip, last_access));
                }
            }
        }
        
        all_entries.sort_by_key(|(_, time)| *time);
        
        let to_evict: Vec<IpAddr> = all_entries.iter()
            .take(count)
            .map(|(ip, _)| *ip)
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

    pub async fn check_rate_limit_detailed(&self, ip: IpAddr) -> RateLimitResult {
        let now = Instant::now();

        match self.state.global_limiter.check_and_increment() {
            RateLimitDecision::Blackholed => return RateLimitResult::Blackholed,
            RateLimitDecision::Limited { limit_type } => {
                return RateLimitResult::Limited {
                    limit_type: limit_type.to_string(),
                    retry_after_millis: 1000,
                };
            }
            RateLimitDecision::Allowed => {}
        }
        
        let slotted_decision = self.state.slotted_ip_limiter.check_and_increment(ip);
        if slotted_decision != RateLimitDecision::Allowed {
            match slotted_decision {
                RateLimitDecision::Limited { limit_type } => {
                    counter!("maluwaf.ratelimit.ip_limited_slotted").increment(1);
                    return RateLimitResult::Limited {
                        limit_type: limit_type.to_string(),
                        retry_after_millis: 1000,
                    };
                }
                RateLimitDecision::Blackholed => return RateLimitResult::Blackholed,
                RateLimitDecision::Allowed => {}
            }
        }

        let shard = self.get_shard(ip);
        let mut requests = shard.ip_requests.write();
        
        let ip_state = requests.entry(ip).or_default();
        
        ip_state.per_second.retain(|t| now.duration_since(*t) < Duration::from_secs(1));
        ip_state.per_minute.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        ip_state.per_5min.retain(|t| now.duration_since(*t) < Duration::from_secs(300));
        ip_state.per_10min.retain(|t| now.duration_since(*t) < Duration::from_secs(600));
        ip_state.per_hour.retain(|t| now.duration_since(*t) < Duration::from_secs(3600));
        ip_state.per_day.retain(|t| now.duration_since(*t) < Duration::from_secs(86400));
        
        let cfg = &self.state.config.ip;
        
        if ip_state.per_second.len() >= cfg.per_second as usize {
            return RateLimitResult::Limited { 
                limit_type: "ip_per_second".to_string(),
                retry_after_millis: 1000,
            };
        }
        if ip_state.per_minute.len() >= cfg.per_minute as usize {
            return RateLimitResult::Limited { 
                limit_type: "ip_per_minute".to_string(),
                retry_after_millis: 60000,
            };
        }
        if ip_state.per_5min.len() >= cfg.per_5min as usize {
            return RateLimitResult::Limited { 
                limit_type: "ip_per_5min".to_string(),
                retry_after_millis: 300000,
            };
        }
        if ip_state.per_10min.len() >= cfg.per_10min as usize {
            return RateLimitResult::Limited { 
                limit_type: "ip_per_10min".to_string(),
                retry_after_millis: 600000,
            };
        }
        if ip_state.per_hour.len() >= cfg.per_hour as usize {
            return RateLimitResult::Limited { 
                limit_type: "ip_per_hour".to_string(),
                retry_after_millis: 3600000,
            };
        }
        if ip_state.per_day.len() >= cfg.per_day as usize {
            return RateLimitResult::Limited { 
                limit_type: "ip_per_day".to_string(),
                retry_after_millis: 86400000,
            };
        }
        
        ip_state.per_second.push(now);
        ip_state.per_minute.push(now);
        ip_state.per_5min.push(now);
        ip_state.per_10min.push(now);
        ip_state.per_hour.push(now);
        ip_state.per_day.push(now);

        let total = *self.state.total_entries.read();
        let max_entries = self.state.memory_config.max_ip_entries;
        
        if total > max_entries {
            tracing::warn!(
                "Rate limiter exceeded max entries ({} > {}), consider increasing limit",
                total,
                max_entries
            );
        }

        RateLimitResult::Allowed
    }

    pub async fn acquire_global_connection(&self) -> Result<GlobalConnectionPermit, ()> {
        match self.state.semaphore.clone().acquire_owned().await {
            Ok(permit) => Ok(GlobalConnectionPermit {
                semaphore: self.state.semaphore.clone(),
                _permit: permit,
            }),
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
    semaphore: Arc<Semaphore>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed,
    Limited { limit_type: String, retry_after_millis: u64 },
    Blackholed,
}
