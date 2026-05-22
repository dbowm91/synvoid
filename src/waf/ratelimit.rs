pub mod core;
pub mod sliding;

use indexmap::IndexMap;
use metrics::counter;
use parking_lot::RwLock;
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

use dashmap::DashMap;

pub struct RateLimiterState {
    pub(crate) site_shards: DashMap<String, Vec<RateLimiterShard>>,
    pub(crate) global_limiter: Arc<GlobalRateLimiter>,
    pub(crate) slotted_ip_limiter: Arc<SlottedIpRateLimiter>,
    pub(crate) semaphore: Arc<Semaphore>,
    pub(crate) config: RateLimitConfigStore,
    pub(crate) memory_config: RateLimitMemoryConfig,
    pub(crate) total_entries: RwLock<usize>,
    pub(crate) lru_order: RwLock<IndexMap<(String, IpAddr), Instant>>,
}

pub(crate) struct RateLimiterShard {
    pub(crate) ip_requests: RwLock<HashMap<IpAddr, IpRateLimitState>>,
    pub(crate) last_cleanup: RwLock<Instant>,
}

#[derive(Default)]
pub(crate) struct IpRateLimitState {
    pub(crate) per_second: RingBuffer<Instant>,
    pub(crate) last_access: Option<Instant>,
}

impl IpRateLimitState {
    #[inline]
    fn is_empty(&self) -> bool {
        self.per_second.is_empty()
    }

    fn remove_expired_windows(&mut self, now: Instant) {
        let cutoff_1s = now - Duration::from_secs(1);
        self.per_second.remove_older_than(cutoff_1s);
    }

    fn touch(&mut self) {
        self.last_access = Some(Instant::now());
    }
}

pub(crate) struct RingBuffer<T> {
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
        
        // Use shared rate limit table if available (Phase 1 Improvement)
        let slotted_ip_limiter = if let Some(table) = crate::upstream::shared_state::SharedRateLimitTable::get_global() {
            tracing::info!("Using shared memory for IP rate limiting");
            Arc::new(SlottedIpRateLimiter::new_shared(
                core_ip_config,
                table.get_mmap(),
            ))
        } else {
            Arc::new(SlottedIpRateLimiter::new(core_ip_config))
        };

        let semaphore = Arc::new(Semaphore::new(global_config.max_connections as usize));

        let state = Arc::new(RateLimiterState {
            site_shards: DashMap::new(),
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
            lru_order: RwLock::new(IndexMap::new()),
        });

        if cleanup_interval_secs > 0 {
            let cleanup_state = state.clone();
            tokio::spawn(async move {
                let mut cleanup_timer = interval(Duration::from_secs(cleanup_interval_secs));
                loop {
                    cleanup_timer.tick().await;
                    let now = Instant::now();
                    let mut total = 0usize;

                    for mut site_entry in cleanup_state.site_shards.iter_mut() {
                        let site_id = site_entry.key().clone();
                        let shards = site_entry.value_mut();
                        for shard in shards {
                            let mut requests = shard.ip_requests.write();
                            let lru_order = &cleanup_state.lru_order;
                            let cutoff_max = Duration::from_secs(86400);
                            requests.retain(|ip, state| {
                                if let Some(last_access) = state.last_access {
                                    if now.duration_since(last_access) > cutoff_max {
                                        return false;
                                    }
                                }
                                state.remove_expired_windows(now);
                                if state.is_empty() {
                                    false
                                } else {
                                    state.touch();
                                    if let Some(lru) =
                                        lru_order.write().get_mut(&(site_id.clone(), *ip))
                                    {
                                        *lru = now;
                                    }
                                    true
                                }
                            });
                            total += requests.len();
                            *shard.last_cleanup.write() = now;
                        }
                    }

                    cleanup_state.slotted_ip_limiter.decay_all(2);
                    let max_entries = cleanup_state.memory_config.max_ip_entries;
                    if total > max_entries {
                        let to_evict = total - max_entries + (max_entries / 10);
                        Self::evict_lru_entries(&cleanup_state, to_evict);
                    }
                    *cleanup_state.total_entries.write() = total;
                }
            });
        }

        RateLimiterManager { state }
    }

    fn evict_lru_entries(state: &Arc<RateLimiterState>, count: usize) {
        let mut lru = state.lru_order.write();
        let to_evict: Vec<(String, IpAddr)> = lru.keys().take(count).cloned().collect();

        for (site_id, ip) in &to_evict {
            if let Some(shards) = state.site_shards.get(site_id) {
                for shard in shards.iter() {
                    if shard.ip_requests.write().remove(ip).is_some() {
                        break;
                    }
                }
            }
        }

        for entry in &to_evict {
            lru.shift_remove(entry);
        }
    }

    pub fn check_global(&self) -> RateLimitResult {
        match self.state.global_limiter.check_and_increment() {
            RateLimitDecision::Allowed => RateLimitResult::Allowed,
            RateLimitDecision::Limited { limit_type } => {
                counter!("synvoid.ratelimit.global_limited").increment(1);
                RateLimitResult::Limited {
                    limit_type: limit_type.to_string(),
                    retry_after_millis: 1000,
                }
            }
            RateLimitDecision::Blackholed => {
                counter!("synvoid.ratelimit.blackholed").increment(1);
                RateLimitResult::Blackholed
            }
        }
    }

    pub fn is_in_blackhole(&self) -> bool {
        self.state.global_limiter.is_in_blackhole()
    }

    pub async fn check_rate_limit(&self, site_id: Option<&str>, ip: IpAddr) -> RateLimitResult {
        // Global IP limit check
        if site_id.is_none() || site_id == Some("global") {
            let decision = self.state.slotted_ip_limiter.check_and_increment(ip);
            if !matches!(decision, RateLimitDecision::Allowed) {
                return match decision {
                    RateLimitDecision::Limited { limit_type } => RateLimitResult::Limited {
                        limit_type: limit_type.to_string(),
                        retry_after_millis: 1000,
                    },
                    _ => RateLimitResult::Blackholed,
                };
            }
        }

        let site_id_str = site_id.unwrap_or("global");

        // Per-site IP limit check (Site Isolation)
        let shards_entry = self
            .state
            .site_shards
            .entry(site_id_str.to_string())
            .or_insert_with(|| {
                let num_shards = self.state.memory_config.num_shards.max(1);
                let mut shards = Vec::with_capacity(num_shards);
                for _ in 0..num_shards {
                    shards.push(RateLimiterShard {
                        ip_requests: RwLock::new(HashMap::new()),
                        last_cleanup: RwLock::new(Instant::now()),
                    });
                }
                shards
            });

        let shards = shards_entry.value();
        let shard_idx = (u64::from_be_bytes(match ip {
            IpAddr::V4(a) => {
                let octets = a.octets();
                [0, 0, 0, 0, octets[0], octets[1], octets[2], octets[3]]
            }
            IpAddr::V6(a) => {
                let octets = a.octets();
                [
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
                    octets[7],
                ]
            }
        }) % shards.len() as u64) as usize;

        let shard = &shards[shard_idx];
        let now = Instant::now();
        let mut requests = shard.ip_requests.write();
        let ip_state = requests.entry(ip).or_insert_with(|| IpRateLimitState {
            per_second: RingBuffer::with_capacity(self.state.config.ip.per_second as usize),
            last_access: Some(now),
        });

        ip_state.remove_expired_windows(now);
        ip_state.touch();

        if ip_state.per_second.len() >= self.state.config.ip.per_second as usize {
            return RateLimitResult::Limited {
                limit_type: "site_ip_per_second".to_string(),
                retry_after_millis: 1000,
            };
        }

        ip_state.per_second.push(now);
        self.state
            .lru_order
            .write()
            .insert((site_id_str.to_string(), ip), now);

        RateLimitResult::Allowed
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

    #[tokio::test]
    async fn test_site_isolation_ratelimit() {
        let manager = RateLimiterManager::new(
            IpRateLimitConfig {
                per_second: 1,
                per_minute: 10,
                per_5min: 50,
                per_10min: 100,
                per_hour: 500,
                per_day: 1000,
                burst: 0,
            },
            GlobalRateLimitConfig {
                per_second: 100,
                per_minute: 1000,
                per_5min: 5000,
                max_connections: 100,
            },
            0,
            RateLimitMemoryConfig::default(),
        );

        let ip: IpAddr = "1.1.1.1".parse().unwrap();

        // Site 1 allowed first request
        assert!(matches!(
            manager.check_rate_limit(Some("site1"), ip).await,
            RateLimitResult::Allowed
        ));
        // Site 1 limited second request
        assert!(matches!(
            manager.check_rate_limit(Some("site1"), ip).await,
            RateLimitResult::Limited { .. }
        ));

        // Site 2 allowed first request for same IP (Isolation!)
        assert!(matches!(
            manager.check_rate_limit(Some("site2"), ip).await,
            RateLimitResult::Allowed
        ));
    }
}
