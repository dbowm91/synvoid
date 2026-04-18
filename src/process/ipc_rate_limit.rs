use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct IpcRateLimiter {
    inner: Arc<IpcRateLimiterInner>,
}

struct IpcRateLimiterInner {
    max_messages_per_second: u64,
    tokens: Mutex<TokenBucket>,
    worker_message_counts: Mutex<std::collections::HashMap<u64, WorkerMessageState>>,
    window_duration: Duration,
    max_workers_tracked: usize,
    last_cleanup: Mutex<Instant>,
    cleanup_interval: Duration,
}

struct WorkerMessageState {
    count: u64,
    window_start: Instant,
}

impl IpcRateLimiter {
    pub fn new(max_messages_per_second: u64, max_burst: u64) -> Self {
        const MAX_WORKERS_TRACKED: usize = 10_000;
        let burst = max_burst.max(max_messages_per_second);
        Self {
            inner: Arc::new(IpcRateLimiterInner {
                max_messages_per_second,
                tokens: Mutex::new(TokenBucket::new(burst, max_messages_per_second)),
                worker_message_counts: Mutex::new(std::collections::HashMap::new()),
                window_duration: Duration::from_secs(1),
                max_workers_tracked: MAX_WORKERS_TRACKED,
                last_cleanup: Mutex::new(Instant::now()),
                cleanup_interval: Duration::from_secs(60),
            }),
        }
    }

    pub fn check(&self) -> Result<(), RateLimitExceeded> {
        let mut tokens = self.inner.tokens.lock();
        tokens.consume(1)
    }

    fn cleanup_stale_entries(
        &self,
        counts: &mut std::collections::HashMap<u64, WorkerMessageState>,
        now: Instant,
    ) {
        let mut last_cleanup = self.inner.last_cleanup.lock();
        if now.duration_since(*last_cleanup) < self.inner.cleanup_interval {
            return;
        }
        *last_cleanup = now;
        drop(last_cleanup);

        counts.retain(|_, state| {
            now.duration_since(state.window_start) < self.inner.window_duration * 3
        });
    }

    pub fn check_worker(&self, worker_id: u64) -> Result<(), RateLimitExceeded> {
        self.check()?;

        let mut counts = self.inner.worker_message_counts.lock();
        let now = Instant::now();

        if counts.len() >= self.inner.max_workers_tracked {
            self.cleanup_stale_entries(&mut counts, now);
            if counts.len() >= self.inner.max_workers_tracked {
                tracing::warn!("IPC rate limiter worker table full, cleaning up");
                return Err(RateLimitExceeded {
                    worker_id,
                    limit: self.inner.max_messages_per_second,
                });
            }
        }

        let state = counts
            .entry(worker_id)
            .or_insert_with(|| WorkerMessageState {
                count: 0,
                window_start: now,
            });

        if now.duration_since(state.window_start) >= self.inner.window_duration {
            state.count = 0;
            state.window_start = now;
        }

        if state.count >= self.inner.max_messages_per_second {
            return Err(RateLimitExceeded {
                worker_id,
                limit: self.inner.max_messages_per_second,
            });
        }

        state.count += 1;
        Ok(())
    }

    pub fn reset_worker(&self, worker_id: u64) {
        let mut counts = self.inner.worker_message_counts.lock();
        counts.remove(&worker_id);
    }
}

struct TokenBucket {
    tokens: u64,
    max_tokens: u64,
    refill_rate: u64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: u64, refill_rate: u64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let ticks = ((elapsed.as_millis() as u64) * self.refill_rate) / 1000;

        if ticks > 0 {
            self.tokens = (self.tokens + ticks).min(self.max_tokens);
            self.last_refill = now;
        }
    }

    fn consume(&mut self, amount: u64) -> Result<(), RateLimitExceeded> {
        self.refill();

        if self.tokens >= amount {
            self.tokens -= amount;
            Ok(())
        } else {
            Err(RateLimitExceeded {
                worker_id: 0,
                limit: self.max_tokens,
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitExceeded {
    pub worker_id: u64,
    pub limit: u64,
}

impl std::fmt::Display for RateLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IPC rate limit exceeded: worker_id={}, limit={}/sec",
            self.worker_id, self.limit
        )
    }
}

impl std::error::Error for RateLimitExceeded {}

pub mod config {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IpcRateLimitConfig {
        #[serde(default = "default_max_messages_per_second")]
        pub max_messages_per_second: u64,
        #[serde(default = "default_max_burst")]
        pub max_burst: u64,
    }

    fn default_max_messages_per_second() -> u64 {
        1000
    }

    fn default_max_burst() -> u64 {
        2000
    }

    impl Default for IpcRateLimitConfig {
        fn default() -> Self {
            Self {
                max_messages_per_second: default_max_messages_per_second(),
                max_burst: default_max_burst(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::IpcRateLimitConfig;

    #[test]
    fn test_rate_limiter_allows_requests() {
        let limiter = IpcRateLimiter::new(100, 100);
        for _ in 0..50 {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excess() {
        let limiter = IpcRateLimiter::new(5, 5);
        for _ in 0..5 {
            let _ = limiter.check();
        }
        let result = limiter.check();
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limiter_worker() {
        let limiter = IpcRateLimiter::new(100, 100);
        for _ in 0..10 {
            assert!(limiter.check_worker(1).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_worker_isolation() {
        let limiter = IpcRateLimiter::new(100, 100);
        for i in 0..5 {
            assert!(limiter.check_worker(i).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_reset_worker() {
        let limiter = IpcRateLimiter::new(100, 100);
        assert!(limiter.check_worker(42).is_ok());
        limiter.reset_worker(42);
    }

    #[test]
    fn test_rate_limit_exceeded_display() {
        let err = RateLimitExceeded {
            worker_id: 1,
            limit: 100,
        };
        let display = format!("{}", err);
        assert!(display.contains("IPC rate limit exceeded"));
        assert!(display.contains("worker_id=1"));
        assert!(display.contains("limit=100"));
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = IpcRateLimitConfig::default();
        assert_eq!(config.max_messages_per_second, 1000);
        assert_eq!(config.max_burst, 2000);
    }

    #[test]
    fn test_zero_limit() {
        let limiter = IpcRateLimiter::new(0, 0);
        let result = limiter.check();
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.limit, 0);
        }
    }

    #[test]
    fn test_very_high_limit() {
        let limiter = IpcRateLimiter::new(1_000_000, 1_000_000);
        for _ in 0..1000 {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn test_burst_allowance() {
        let limiter = IpcRateLimiter::new(10, 100);
        for _ in 0..100 {
            assert!(limiter.check().is_ok());
        }
        let result = limiter.check();
        assert!(result.is_err());
    }

    #[test]
    fn test_burst_greater_than_rate() {
        let limiter = IpcRateLimiter::new(10, 50);
        for _ in 0..50 {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn test_worker_rate_limit() {
        let limiter = IpcRateLimiter::new(3, 10000);
        assert!(limiter.check_worker(0).is_ok());
        assert!(limiter.check_worker(0).is_ok());
        assert!(limiter.check_worker(0).is_ok());
        let result = limiter.check_worker(0);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.worker_id, 0);
        }
    }

    #[test]
    fn test_worker_isolation_per_worker() {
        let limiter = IpcRateLimiter::new(3, 10000);
        assert!(limiter.check_worker(1).is_ok());
        assert!(limiter.check_worker(1).is_ok());
        assert!(limiter.check_worker(1).is_ok());
        assert!(limiter.check_worker(1).is_err());

        let limiter2 = IpcRateLimiter::new(3, 10000);
        assert!(limiter2.check_worker(2).is_ok());
        assert!(limiter2.check_worker(2).is_ok());
        assert!(limiter2.check_worker(2).is_ok());
        assert!(limiter2.check_worker(2).is_err());
    }

    #[test]
    fn test_reset_nonexistent_worker() {
        let limiter = IpcRateLimiter::new(100, 100);
        limiter.reset_worker(999);
    }

    #[test]
    fn test_reset_worker_after_limit() {
        let limiter = IpcRateLimiter::new(3, 10000);
        assert!(limiter.check_worker(0).is_ok());
        assert!(limiter.check_worker(0).is_ok());
        assert!(limiter.check_worker(0).is_ok());
        assert!(limiter.check_worker(0).is_err());
        limiter.reset_worker(0);
        assert!(limiter.check_worker(0).is_ok());
    }

    #[test]
    fn test_worker_message_counts_tracking() {
        let limiter = IpcRateLimiter::new(3, 10000);
        assert!(limiter.check_worker(1).is_ok());
        assert!(limiter.check_worker(1).is_ok());
        assert!(limiter.check_worker(1).is_ok());
        assert!(limiter.check_worker(1).is_err());
    }

    #[test]
    fn test_max_workers_tracked_prevents_new() {
        let limiter = IpcRateLimiter::new(100000, 100000);
        for i in 0..10000 {
            assert!(limiter.check_worker(i as u64).is_ok());
        }
    }

    #[test]
    fn test_multiple_workers_same_limit() {
        let limiter = IpcRateLimiter::new(3, 10000);
        for worker in 0..10 {
            assert!(limiter.check_worker(worker).is_ok());
            assert!(limiter.check_worker(worker).is_ok());
            assert!(limiter.check_worker(worker).is_ok());
            assert!(limiter.check_worker(worker).is_err());
        }
    }

    #[test]
    fn test_rate_limit_exceeded_error_fields() {
        let err = RateLimitExceeded {
            worker_id: 42,
            limit: 500,
        };
        assert_eq!(err.worker_id, 42);
        assert_eq!(err.limit, 500);
    }

    #[test]
    fn test_rate_limit_exceeded_error_display() {
        let err = RateLimitExceeded {
            worker_id: 123,
            limit: 456,
        };
        let display = format!("{}", err);
        assert!(display.contains("123"));
        assert!(display.contains("456"));
        assert!(display.contains("IPC rate limit exceeded"));
    }

    #[test]
    fn test_rate_limit_exceeded_error_debug() {
        let err = RateLimitExceeded {
            worker_id: 1,
            limit: 100,
        };
        let debug = format!("{:?}", err);
        assert!(debug.contains("worker_id"));
        assert!(debug.contains("limit"));
    }

    #[test]
    fn test_rate_limit_exceeded_error_source() {
        use std::error::Error;
        let err = RateLimitExceeded {
            worker_id: 1,
            limit: 100,
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn test_config_serialization() {
        let config = IpcRateLimitConfig {
            max_messages_per_second: 500,
            max_burst: 1000,
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("500"));
        assert!(json.contains("1000"));
    }

    #[test]
    fn test_config_deserialization() {
        let json = r#"{"max_messages_per_second": 2000, "max_burst": 4000}"#;
        let config: IpcRateLimitConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_messages_per_second, 2000);
        assert_eq!(config.max_burst, 4000);
    }

    #[test]
    fn test_config_default_serialization() {
        let config = IpcRateLimitConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("1000"));
        assert!(json.contains("2000"));
    }

    #[test]
    fn test_check_and_check_worker_independent() {
        let limiter = IpcRateLimiter::new(100000, 100000);
        for _ in 0..50 {
            assert!(limiter.check().is_ok());
        }
        for _ in 0..100 {
            assert!(limiter.check_worker(1).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_clone_independence() {
        let limiter1 = IpcRateLimiter::new(1000, 1000);
        let limiter2 = limiter1.clone();
        for _ in 0..500 {
            assert!(limiter1.check().is_ok());
        }
        for _ in 0..500 {
            assert!(limiter2.check().is_ok());
        }
        assert!(limiter1.check().is_err());
        assert!(limiter2.check().is_err());
    }

    #[test]
    fn test_check_worker_after_check() {
        let limiter = IpcRateLimiter::new(10, 10);
        assert!(limiter.check().is_ok());
        assert!(limiter.check_worker(1).is_ok());
        assert!(limiter.check_worker(1).is_ok());
    }

    #[test]
    fn test_concurrent_access_basic() {
        use std::sync::Arc;
        use std::thread;

        let limiter = Arc::new(IpcRateLimiter::new(1000, 1000));
        let mut handles = vec![];

        for t in 0..4 {
            let lim = Arc::clone(&limiter);
            let handle = thread::spawn(move || {
                for _ in 0..250 {
                    let _ = lim.check();
                }
                for i in 0..10 {
                    let _ = lim.check_worker(t * 100 + i);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_worker_access() {
        use std::sync::Arc;
        use std::thread;

        let limiter = Arc::new(IpcRateLimiter::new(100, 100));
        let mut handles = vec![];

        for worker_id in 0..10 {
            let lim = Arc::clone(&limiter);
            let handle = thread::spawn(move || {
                for _ in 0..20 {
                    let _ = lim.check_worker(worker_id);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_clone_allows_concurrent_shared_state() {
        let original = IpcRateLimiter::new(10, 10);
        let clone1 = original.clone();
        let clone2 = original.clone();
        let clone3 = original.clone();

        let _ = clone1.check();
        let _ = clone2.check();
        let _ = clone3.check();
    }
}
