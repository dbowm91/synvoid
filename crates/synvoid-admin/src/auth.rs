//! Admin API token authentication.
//!
//! Provides bcrypt-based admin token hashing/verification and
//! brute-force rate limiting for the admin API.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAX_AUTH_ATTEMPTS: usize = 5;
pub const AUTH_LOCKOUT_DURATION: Duration = Duration::from_secs(300);
const AUTH_WINDOW_DURATION: Duration = Duration::from_secs(60);
const BCRYPT_COST: u32 = 12;

pub struct AuthRateLimiter {
    attempts: Arc<RwLock<HashMap<String, AuthAttemptState>>>,
}

struct AuthAttemptState {
    times: Vec<Instant>,
    locked_at: Option<Instant>,
}

pub fn hash_admin_token_with_cost(token: &str, cost: u32) -> Result<String, String> {
    bcrypt::hash(token, cost).map_err(|e| format!("bcrypt hashing failed: {}", e))
}

pub fn hash_admin_token(token: &str) -> Result<String, String> {
    hash_admin_token_with_cost(token, BCRYPT_COST)
}

pub fn verify_admin_token(token: &str, hash: &str) -> bool {
    bcrypt::verify(token, hash).unwrap_or(false)
}

impl AuthRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn record_failure(&self, identifier: &str) {
        let mut attempts = self.attempts.write();
        // Inline cleanup that previously required a separate write lock (TOCTOU).
        if let Some(state) = attempts.get_mut(identifier) {
            state.times.retain(|t| t.elapsed() < AUTH_WINDOW_DURATION);
            if state.times.is_empty() && state.locked_at.is_none() {
                attempts.remove(identifier);
            }
        }
        if attempts
            .get(identifier)
            .map(|e| {
                e.times
                    .iter()
                    .filter(|t| t.elapsed() < AUTH_WINDOW_DURATION)
                    .count()
            })
            .unwrap_or(0)
            >= MAX_AUTH_ATTEMPTS
        {
            return;
        }
        let entry = attempts
            .entry(identifier.to_string())
            .or_insert_with(|| AuthAttemptState {
                times: Vec::new(),
                locked_at: None,
            });
        entry.times.push(Instant::now());

        let recent: Vec<_> = entry
            .times
            .iter()
            .filter(|t| t.elapsed() < AUTH_WINDOW_DURATION)
            .cloned()
            .collect();
        entry.times = recent;

        if entry.times.len() >= MAX_AUTH_ATTEMPTS && entry.locked_at.is_none() {
            entry.locked_at = Some(Instant::now());
            let attempts = Arc::clone(&self.attempts);
            let id = identifier.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(AUTH_LOCKOUT_DURATION).await;
                let mut attempts = attempts.write();
                attempts.remove(&id);
            });
        }
    }

    pub fn record_success(&self, identifier: &str) {
        let mut attempts = self.attempts.write();
        attempts.remove(identifier);
    }

    pub fn is_locked(&self, identifier: &str) -> bool {
        let attempts = self.attempts.read();
        attempts
            .get(identifier)
            .and_then(|state| state.locked_at)
            .is_some()
    }

    pub fn retry_after(&self, identifier: &str) -> Option<Duration> {
        let attempts = self.attempts.read();
        if let Some(state) = attempts.get(identifier) {
            if let Some(locked_at) = state.locked_at {
                let elapsed = locked_at.elapsed();
                if elapsed >= AUTH_LOCKOUT_DURATION {
                    return Some(Duration::ZERO);
                }
                return Some(AUTH_LOCKOUT_DURATION.saturating_sub(elapsed));
            }
        }
        None
    }

    pub fn cleanup_expired(&self) {
        let mut attempts = self.attempts.write();
        let now = Instant::now();
        attempts.retain(|_, state| {
            if state.locked_at.is_some() {
                return true;
            }
            state
                .times
                .retain(|t| now.duration_since(*t) < AUTH_WINDOW_DURATION);
            !state.times.is_empty()
        });
    }

    #[allow(dead_code)]
    fn cleanup_if_needed(&self, identifier: &str) {
        let mut attempts = self.attempts.write();
        if let Some(state) = attempts.get_mut(identifier) {
            state.times.retain(|t| t.elapsed() < AUTH_WINDOW_DURATION);
            if state.times.is_empty() && state.locked_at.is_none() {
                attempts.remove(identifier);
            }
        }
    }
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub static AUTH_RATE_LIMITER: std::sync::LazyLock<AuthRateLimiter> =
    std::sync::LazyLock::new(AuthRateLimiter::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_admin_token() {
        let token = "test_admin_token";
        let hash = hash_admin_token(token).unwrap();

        assert!(!hash.is_empty());
        assert_ne!(hash, token);
        assert!(hash.starts_with("$2"));
    }

    #[test]
    fn test_verify_admin_token_valid() {
        let token = "my_secret_token";
        let hash = hash_admin_token(token).unwrap();

        assert!(verify_admin_token(token, &hash));
    }

    #[test]
    fn test_verify_admin_token_invalid() {
        let token = "my_secret_token";
        let hash = hash_admin_token(token).unwrap();

        assert!(!verify_admin_token("wrong_token", &hash));
    }

    #[test]
    fn test_verify_admin_token_invalid_hash() {
        assert!(!verify_admin_token("token", "invalid_hash"));
    }

    #[test]
    fn test_auth_rate_limiter_record_failure() {
        let limiter = AuthRateLimiter::new();
        let identifier = "192.168.1.100";

        limiter.record_failure(identifier);

        let attempts = limiter.attempts.read();
        assert!(attempts.contains_key(identifier));
    }

    #[test]
    fn test_auth_rate_limiter_record_failure_multiple() {
        let limiter = AuthRateLimiter::new();
        let identifier = "192.168.1.101";

        for _ in 0..3 {
            limiter.record_failure(identifier);
        }

        let attempts = limiter.attempts.read();
        let entry = attempts.get(identifier);
        assert!(entry.is_some());
        assert!(entry.unwrap().times.len() <= MAX_AUTH_ATTEMPTS);
    }

    #[test]
    fn test_auth_rate_limiter_record_success() {
        let limiter = AuthRateLimiter::new();
        let identifier = "192.168.1.102";

        limiter.record_failure(identifier);
        limiter.record_failure(identifier);

        limiter.record_success(identifier);

        let attempts = limiter.attempts.read();
        assert!(!attempts.contains_key(identifier));
    }

    #[test]
    fn test_auth_rate_limiter_cleanup_expired() {
        let limiter = AuthRateLimiter::new();
        let identifier = "192.168.1.103";

        limiter.record_failure(identifier);
        limiter.cleanup_expired();

        let attempts = limiter.attempts.read();
        assert!(attempts.contains_key(identifier));
    }

    #[test]
    fn test_hash_admin_token_with_cost() {
        let token = "test_token";
        let hash_low = hash_admin_token_with_cost(token, 4).unwrap();
        let hash_high = hash_admin_token_with_cost(token, 12).unwrap();

        assert!(!hash_low.is_empty());
        assert!(!hash_high.is_empty());
    }

    #[test]
    fn test_auth_rate_limiter_separate_identifiers() {
        let limiter = AuthRateLimiter::new();

        limiter.record_failure("192.168.1.1");
        limiter.record_failure("192.168.1.2");

        let attempts = limiter.attempts.read();
        assert_eq!(attempts.len(), 2);
    }

    #[tokio::test]
    async fn test_auth_rate_limiter_is_locked() {
        let limiter = AuthRateLimiter::new();
        let identifier = "192.168.1.104";

        for _ in 0..MAX_AUTH_ATTEMPTS {
            limiter.record_failure(identifier);
        }

        assert!(limiter.is_locked(identifier));
    }

    #[tokio::test]
    async fn test_auth_rate_limiter_is_locked_not_expired() {
        let limiter = AuthRateLimiter::new();
        let identifier = "192.168.1.105";

        for _ in 0..MAX_AUTH_ATTEMPTS {
            limiter.record_failure(identifier);
        }

        assert!(limiter.is_locked(identifier));

        let retry = limiter.retry_after(identifier);
        assert!(retry.is_some());
    }

    #[test]
    fn test_auth_rate_limiter_retry_after_none_when_not_locked() {
        let limiter = AuthRateLimiter::new();
        let identifier = "192.168.1.106";

        assert!(limiter.retry_after(identifier).is_none());
    }

    #[test]
    fn test_auth_rate_limiter_retry_after_uses_lock_time() {
        let limiter = AuthRateLimiter::new();
        let identifier = "192.168.1.108";
        let locked_at = Instant::now() - Duration::from_secs(10);

        limiter.attempts.write().insert(
            identifier.to_string(),
            AuthAttemptState {
                times: vec![Instant::now()],
                locked_at: Some(locked_at),
            },
        );

        let retry = limiter.retry_after(identifier).expect("locked identifier");
        let lower = AUTH_LOCKOUT_DURATION.saturating_sub(Duration::from_secs(11));
        let upper = AUTH_LOCKOUT_DURATION.saturating_sub(Duration::from_secs(9));
        assert!(
            retry >= lower && retry <= upper,
            "retry-after should be anchored to lock time: {retry:?}"
        );
    }

    #[test]
    fn test_auth_rate_limiter_is_locked_false_before_threshold() {
        let limiter = AuthRateLimiter::new();
        let identifier = "192.168.1.107";

        for _ in 0..(MAX_AUTH_ATTEMPTS - 1) {
            limiter.record_failure(identifier);
        }

        assert!(!limiter.is_locked(identifier));
    }
}
