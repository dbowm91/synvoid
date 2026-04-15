use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_AUTH_ATTEMPTS: usize = 5;
const AUTH_LOCKOUT_DURATION: Duration = Duration::from_secs(300);
const AUTH_WINDOW_DURATION: Duration = Duration::from_secs(60);
const BCRYPT_COST: u32 = 12;

pub struct AuthRateLimiter {
    #[allow(clippy::type_complexity)]
    attempts: Arc<RwLock<HashMap<String, (Vec<Instant>, bool)>>>,
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
        if attempts
            .get(identifier)
            .map(|e| {
                e.0.iter()
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
            .or_insert((Vec::new(), false));
        entry.0.push(Instant::now());

        let recent: Vec<_> = entry
            .0
            .iter()
            .filter(|t| t.elapsed() < AUTH_WINDOW_DURATION)
            .cloned()
            .collect();
        entry.0 = recent;

        if entry.0.len() >= MAX_AUTH_ATTEMPTS {
            entry.1 = true;
            let attempts = Arc::clone(&self.attempts);
            let id = identifier.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(AUTH_LOCKOUT_DURATION).await;
                let mut attempts = attempts.write();
                if let Some((_, locked)) = attempts.get_mut(&id) {
                    *locked = false;
                }
                attempts.remove(&id);
            });
        }
    }

    pub fn record_success(&self, identifier: &str) {
        let mut attempts = self.attempts.write();
        attempts.remove(identifier);
    }

    pub fn cleanup_expired(&self) {
        let mut attempts = self.attempts.write();
        let now = Instant::now();
        attempts.retain(|_, (times, locked)| {
            if *locked {
                return true;
            }
            times.retain(|t| now.duration_since(*t) < AUTH_LOCKOUT_DURATION);
            !times.is_empty()
        });
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
        let (times, _) = entry.unwrap();
        assert!(times.len() <= MAX_AUTH_ATTEMPTS);
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
}
