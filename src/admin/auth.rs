use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_AUTH_ATTEMPTS: usize = 5;
const AUTH_LOCKOUT_DURATION: Duration = Duration::from_secs(300);
const AUTH_WINDOW_DURATION: Duration = Duration::from_secs(60);

pub struct AuthRateLimiter {
    attempts: Arc<RwLock<HashMap<String, (Vec<Instant>, bool)>>>,
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
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub static AUTH_RATE_LIMITER: std::sync::LazyLock<AuthRateLimiter> = 
    std::sync::LazyLock::new(AuthRateLimiter::new);

pub fn require_auth(
    auth: &Option<TypedHeader<Authorization<Bearer>>>,
    expected_token: &str,
    client_ip: Option<&str>,
) -> bool {
    let client_id = client_ip.unwrap_or("unknown");
    
    if !AUTH_RATE_LIMITER.check(client_id) {
        tracing::warn!("Authentication rate limit exceeded for {} - too many failed attempts", client_id);
        return false;
    }
    
    let result = match auth {
        Some(TypedHeader(auth_header)) => {
            let token = auth_header.token();
            constant_time_compare(token, expected_token)
        }
        None => false,
    };
    
    if !result {
        AUTH_RATE_LIMITER.record_failure(client_id);
    } else {
        AUTH_RATE_LIMITER.record_success(client_id);
    }
    
    result
}

pub fn constant_time_compare(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    // Use constant-time comparison to avoid timing attacks
    // that could leak information about token length
    a_bytes.ct_eq(b_bytes).into()
}

pub type OptionalAuth = Option<TypedHeader<Authorization<Bearer>>>;
