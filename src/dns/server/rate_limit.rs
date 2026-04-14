use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::RwLock as PLRwLock;

/// Error type returned when a rate limit is exceeded.
#[derive(Debug, Clone, Copy)]
pub struct RateLimited;

const MAX_IP_BUCKETS: usize = 100000;
const MAX_RRL_BUCKETS: usize = 100000;
const CLEANUP_INTERVAL_SECS: u64 = 60;
const BUCKET_EXPIRY_SECS: u64 = 300;

struct TokenBucket {
    tokens: u64,
    max_tokens: u64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: u64, refill_per_second: u64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate: refill_per_second as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        let tokens_to_add = (elapsed * self.refill_rate) as u64;
        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.max_tokens);
            self.last_refill = now;
        }
    }
}

struct TimedTokenBucket {
    bucket: TokenBucket,
    last_access: Instant,
}

impl TimedTokenBucket {
    fn new(bucket: TokenBucket) -> Self {
        Self {
            bucket,
            last_access: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.last_access.elapsed().as_secs() > BUCKET_EXPIRY_SECS
    }

    fn try_consume(&mut self) -> bool {
        self.last_access = Instant::now();
        self.bucket.try_consume()
    }

    fn last_access_time(&self) -> Instant {
        self.last_access
    }
}

struct TimedBucketMap<K: Eq + std::hash::Hash + Clone> {
    buckets: std::collections::HashMap<K, TimedTokenBucket>,
    max_buckets: usize,
    cleanup_batch_size: usize,
}

impl<K: Eq + std::hash::Hash + Clone> TimedBucketMap<K> {
    fn new(max_buckets: usize, cleanup_batch_size: usize) -> Self {
        Self {
            buckets: std::collections::HashMap::new(),
            max_buckets,
            cleanup_batch_size,
        }
    }

    fn get_or_insert_with<F: FnOnce() -> TimedTokenBucket>(
        &mut self,
        key: &K,
        f: F,
    ) -> &mut TimedTokenBucket {
        self.buckets.entry(key.clone()).or_insert_with(f)
    }

    fn cleanup(&mut self) {
        self.buckets.retain(|_, v| !v.is_expired());

        if self.buckets.len() > self.max_buckets {
            let excess = self.buckets.len() - self.max_buckets / 2;
            let mut items: Vec<_> = self
                .buckets
                .iter()
                .map(|(k, v)| (k.clone(), v.last_access_time()))
                .collect();
            items.sort_by(|a, b| a.1.cmp(&b.1));

            for (key, _) in items.into_iter().take(excess.min(self.cleanup_batch_size)) {
                self.buckets.remove(&key);
            }
        }
    }

    fn is_over_limit(&self, limit: usize) -> bool {
        self.buckets.len() >= limit
    }
}

pub struct DnsRateLimiter {
    global_bucket: PLRwLock<TokenBucket>,
    ip_buckets: PLRwLock<TimedBucketMap<IpAddr>>,
    rrl_buckets: PLRwLock<TimedBucketMap<String>>,
    rrl_source_buckets: PLRwLock<TimedBucketMap<IpAddr>>,
    rrl_threshold: u64,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    rrl_window: Duration,
    last_cleanup: PLRwLock<Instant>,
}

impl DnsRateLimiter {
    pub fn new(per_second: u64, max_burst: u64) -> Self {
        Self {
            global_bucket: PLRwLock::new(TokenBucket::new(max_burst, per_second)),
            ip_buckets: PLRwLock::new(TimedBucketMap::new(MAX_IP_BUCKETS, 1000)),
            rrl_buckets: PLRwLock::new(TimedBucketMap::new(MAX_RRL_BUCKETS, 1000)),
            rrl_source_buckets: PLRwLock::new(TimedBucketMap::new(MAX_RRL_BUCKETS, 1000)),
            rrl_threshold: 100,
            rrl_window: Duration::from_secs(5),
            last_cleanup: PLRwLock::new(Instant::now()),
        }
    }

    fn cleanup_if_needed(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = *self.last_cleanup.read();
            now.duration_since(last).as_secs() >= CLEANUP_INTERVAL_SECS
        };

        if !should_cleanup {
            return;
        }

        self.ip_buckets.write().cleanup();
        self.rrl_buckets.write().cleanup();
        self.rrl_source_buckets.write().cleanup();

        *self.last_cleanup.write() = now;
    }

    pub fn check(&self) -> Result<(), RateLimited> {
        if self.global_bucket.write().try_consume() {
            Ok(())
        } else {
            Err(RateLimited)
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<(), RateLimited> {
        if self.check().is_err() {
            return Err(RateLimited);
        }

        self.cleanup_if_needed();

        let mut buckets = self.ip_buckets.write();

        if buckets.is_over_limit(MAX_IP_BUCKETS) {
            return Err(RateLimited);
        }

        let bucket =
            buckets.get_or_insert_with(&ip, || TimedTokenBucket::new(TokenBucket::new(10, 10)));
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(RateLimited)
        }
    }

    pub fn check_rrl(&self, source_ip: IpAddr) -> Result<(), RateLimited> {
        self.cleanup_if_needed();

        let mut buckets = self.rrl_source_buckets.write();

        if buckets.is_over_limit(MAX_RRL_BUCKETS) {
            return Err(RateLimited);
        }

        let bucket = buckets.get_or_insert_with(&source_ip, || {
            TimedTokenBucket::new(TokenBucket::new(
                self.rrl_threshold * 10,
                self.rrl_threshold,
            ))
        });
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(RateLimited)
        }
    }

    pub fn should_respond(&self, source_ip: IpAddr) -> bool {
        self.cleanup_if_needed();

        let mut buckets = self.rrl_source_buckets.write();

        if buckets.is_over_limit(MAX_RRL_BUCKETS) {
            return false;
        }

        let bucket = buckets.get_or_insert_with(&source_ip, || {
            TimedTokenBucket::new(TokenBucket::new(
                self.rrl_threshold * 10,
                self.rrl_threshold,
            ))
        });

        if bucket.try_consume() {
            true
        } else {
            tracing::debug!("RRL drop response to {}", source_ip);
            false
        }
    }
}
