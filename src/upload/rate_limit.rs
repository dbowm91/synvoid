use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_uploads_per_minute: u32,
    pub max_uploads_per_hour: u32,
    pub max_bytes_per_minute: u64,
    pub burst_allowance: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_uploads_per_minute: 30,
            max_uploads_per_hour: 200,
            max_bytes_per_minute: 100 * 1024 * 1024,
            burst_allowance: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UploadRateLimitState {
    pub uploads_last_minute: u32,
    pub uploads_last_hour: u32,
    pub bytes_last_minute: u64,
    pub first_upload_time: Option<Instant>,
    pub minute_reset_time: Instant,
    pub hour_reset_time: Instant,
    pub minute_upload_count: u32,
    pub minute_byte_count: u64,
    pub hour_upload_count: u32,
    pub blocked: bool,
}

impl Default for UploadRateLimitState {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            uploads_last_minute: 0,
            uploads_last_hour: 0,
            bytes_last_minute: 0,
            first_upload_time: None,
            minute_reset_time: now,
            hour_reset_time: now,
            minute_upload_count: 0,
            minute_byte_count: 0,
            hour_upload_count: 0,
            blocked: false,
        }
    }
}

pub struct UploadRateLimiter {
    config: RateLimitConfig,
    client_states: Arc<RwLock<HashMap<String, UploadRateLimitState>>>,
    cleanup_interval_secs: u64,
    last_cleanup_ts: AtomicU64,
}

impl Default for UploadRateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl UploadRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            client_states: Arc::new(RwLock::new(HashMap::new())),
            cleanup_interval_secs: 300,
            last_cleanup_ts: AtomicU64::new(0),
        }
    }

    pub fn check_rate_limit(&self, client_id: &str, file_size: u64) -> RateLimitResult {
        self.cleanup_if_needed();

        let mut states = self.client_states.write();
        let state = states.entry(client_id.to_string()).or_insert_with(|| {
            let now = Instant::now();
            UploadRateLimitState {
                minute_reset_time: now,
                hour_reset_time: now,
                ..Default::default()
            }
        });

        self.check_and_update_limits(state, file_size)
    }

    fn check_and_update_limits(
        &self,
        state: &mut UploadRateLimitState,
        file_size: u64,
    ) -> RateLimitResult {
        let now = Instant::now();
        let minute_elapsed = now.duration_since(state.minute_reset_time).as_secs() >= 60;
        let hour_elapsed = now.duration_since(state.hour_reset_time).as_secs() >= 3600;

        if minute_elapsed {
            state.uploads_last_minute = state.minute_upload_count;
            state.bytes_last_minute = state.minute_byte_count;
            state.minute_upload_count = 0;
            state.minute_byte_count = 0;
            state.minute_reset_time = now;
        }

        if hour_elapsed {
            state.uploads_last_hour = state.hour_upload_count;
            state.hour_upload_count = 0;
            state.hour_reset_time = now;
        }

        if state.first_upload_time.is_none() {
            state.first_upload_time = Some(now);
        }

        if state.blocked {
            let cooldown = Duration::from_secs(300);
            if let Some(first_time) = state.first_upload_time {
                if now.duration_since(first_time) > cooldown {
                    state.blocked = false;
                } else {
                    return RateLimitResult::Blocked {
                        reason: RateLimitReason::ExceededHourlyLimit,
                        retry_after: Some(300 - now.duration_since(first_time).as_secs()),
                    };
                }
            }
        }

        let effective_minute_limit =
            self.config.max_uploads_per_minute + self.config.burst_allowance;
        let effective_hour_limit =
            self.config.max_uploads_per_hour + (self.config.burst_allowance * 2);

        if state.minute_upload_count >= self.config.max_uploads_per_minute {
            return RateLimitResult::RateLimited {
                reason: RateLimitReason::ExceededMinuteLimit,
                current: state.minute_upload_count as u64,
                limit: self.config.max_uploads_per_minute as u64,
                window: "minute".to_string(),
                retry_after_secs: Some(60),
            };
        }

        if state.hour_upload_count >= self.config.max_uploads_per_hour {
            state.blocked = true;
            return RateLimitResult::Blocked {
                reason: RateLimitReason::ExceededHourlyLimit,
                retry_after: Some(3600 - now.duration_since(state.hour_reset_time).as_secs()),
            };
        }

        if state.minute_byte_count + file_size > self.config.max_bytes_per_minute {
            return RateLimitResult::RateLimited {
                reason: RateLimitReason::ExceededMinuteBytes,
                current: state.minute_byte_count as u64,
                limit: self.config.max_bytes_per_minute,
                window: "minute".to_string(),
                retry_after_secs: Some(60),
            };
        }

        state.minute_upload_count += 1;
        state.hour_upload_count += 1;
        state.minute_byte_count += file_size;

        RateLimitResult::Allowed {
            uploads_remaining_minute: effective_minute_limit
                .saturating_sub(state.minute_upload_count),
            uploads_remaining_hour: effective_hour_limit.saturating_sub(state.hour_upload_count),
            bytes_remaining_minute: self
                .config
                .max_bytes_per_minute
                .saturating_sub(state.minute_byte_count),
        }
    }

    fn cleanup_if_needed(&self) {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let last_cleanup = self.last_cleanup_ts.load(Ordering::Relaxed);
        if now_secs - last_cleanup > self.cleanup_interval_secs {
            let mut states = self.client_states.write();
            states.retain(|_, state| {
                let state_age = now_secs.saturating_sub(state.hour_reset_time.elapsed().as_secs());
                state_age < 7200
            });
            drop(states);
            self.last_cleanup_ts.store(now_secs, Ordering::Relaxed);
        }
    }

    pub fn get_stats(&self, client_id: &str) -> Option<UploadRateLimitState> {
        let states = self.client_states.read();
        states.get(client_id).cloned()
    }

    pub fn reset_client(&self, client_id: &str) {
        let mut states = self.client_states.write();
        states.remove(client_id);
    }
}

#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed {
        uploads_remaining_minute: u32,
        uploads_remaining_hour: u32,
        bytes_remaining_minute: u64,
    },
    RateLimited {
        reason: RateLimitReason,
        current: u64,
        limit: u64,
        window: String,
        retry_after_secs: Option<u64>,
    },
    Blocked {
        reason: RateLimitReason,
        retry_after: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitReason {
    ExceededMinuteLimit,
    ExceededHourlyLimit,
    ExceededMinuteBytes,
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, RateLimitResult::Blocked { .. })
    }

    pub fn is_rate_limited(&self) -> bool {
        matches!(self, RateLimitResult::RateLimited { .. })
    }
}

pub fn create_rate_limiter(config: RateLimitConfig) -> UploadRateLimiter {
    UploadRateLimiter::new(config)
}

pub fn default_rate_limit_config() -> RateLimitConfig {
    RateLimitConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allowed() {
        let config = RateLimitConfig {
            max_uploads_per_minute: 10,
            max_uploads_per_hour: 100,
            max_bytes_per_minute: 50 * 1024 * 1024,
            burst_allowance: 2,
        };
        let limiter = UploadRateLimiter::new(config);

        let result = limiter.check_rate_limit("test_client", 1024);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_rate_limit_minute_exceeded() {
        let config = RateLimitConfig {
            max_uploads_per_minute: 2,
            max_uploads_per_hour: 100,
            max_bytes_per_minute: 50 * 1024 * 1024,
            burst_allowance: 0,
        };
        let limiter = UploadRateLimiter::new(config);

        let _ = limiter.check_rate_limit("test_client", 1024);
        let _ = limiter.check_rate_limit("test_client", 1024);
        let result = limiter.check_rate_limit("test_client", 1024);

        assert!(result.is_rate_limited());
    }

    #[test]
    fn test_rate_limit_different_clients() {
        let config = RateLimitConfig {
            max_uploads_per_minute: 2,
            max_uploads_per_hour: 100,
            max_bytes_per_minute: 50 * 1024 * 1024,
            burst_allowance: 0,
        };
        let limiter = UploadRateLimiter::new(config);

        let _ = limiter.check_rate_limit("client1", 1024);
        let _ = limiter.check_rate_limit("client1", 1024);
        let result = limiter.check_rate_limit("client1", 1024);
        assert!(result.is_rate_limited());

        let result2 = limiter.check_rate_limit("client2", 1024);
        assert!(result2.is_allowed());
    }

    #[test]
    fn test_rate_limit_byte_limit() {
        let config = RateLimitConfig {
            max_uploads_per_minute: 100,
            max_uploads_per_hour: 1000,
            max_bytes_per_minute: 2048,
            burst_allowance: 0,
        };
        let limiter = UploadRateLimiter::new(config);

        let result = limiter.check_rate_limit("test_client", 1024);
        assert!(result.is_allowed());

        let result = limiter.check_rate_limit("test_client", 1025);
        assert!(result.is_rate_limited());
    }
}
