use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_AUTH_ATTEMPTS: usize = 5;
const AUTH_LOCKOUT_DURATION: Duration = Duration::from_secs(300);
const AUTH_WINDOW_DURATION: Duration = Duration::from_secs(60);
const BCRYPT_COST: u32 = 4;

pub struct AuthRateLimiter {
    attempts: Arc<RwLock<HashMap<String, (Vec<Instant>, bool)>>>,
}

pub fn hash_admin_token(token: &str) -> String {
    match bcrypt::hash(token, BCRYPT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!(
                "bcrypt hashing failed ({}), falling back to plaintext comparison — \
                 this is less secure but allows the admin API to function",
                e
            );
            // Return token prefixed with a marker so verify_admin_token can detect the fallback
            format!("__plaintext__:{}", token)
        }
    }
}

pub fn verify_admin_token(token: &str, hash: &str) -> bool {
    // Detect plaintext fallback (bcrypt failed during startup)
    if let Some(plain_hash) = hash.strip_prefix("__plaintext__:") {
        return token == plain_hash;
    }
    bcrypt::verify(token, hash).unwrap_or(false)
}

impl AuthRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn check(&self, identifier: &str) -> bool {
        let attempts = self.attempts.read();
        if let Some((times, locked)) = attempts.get(identifier) {
            if *locked {
                return false;
            }
            let recent: Vec<_> = times
                .iter()
                .filter(|t| t.elapsed() < AUTH_WINDOW_DURATION)
                .collect();
            recent.len() < MAX_AUTH_ATTEMPTS
        } else {
            true
        }
    }

    pub fn record_failure(&self, identifier: &str) {
        let mut attempts = self.attempts.write();
        let entry = attempts.entry(identifier.to_string()).or_insert((Vec::new(), false));
        entry.0.push(Instant::now());
        
        let recent: Vec<_> = entry.0
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


