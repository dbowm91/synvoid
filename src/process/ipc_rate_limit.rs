use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct IpcRateLimiter {
    inner: Arc<IpcRateLimiterInner>,
}

struct IpcRateLimiterInner {
    max_messages_per_second: u64,
    #[allow(dead_code)] // Reserved for future burst configuration
    max_burst: u64,
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
                max_burst: burst,
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
}
