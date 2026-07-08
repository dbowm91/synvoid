use crate::config::AiBudgetConfig;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Budget enforcement errors returned before provider calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetExceeded {
    PromptTooLarge { limit: usize, actual: usize },
    CircuitOpen { failures: usize },
    ConcurrencyLimit,
    TurnsExceeded { limit: usize },
}

impl std::fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PromptTooLarge { limit, actual } => {
                write!(f, "prompt {} bytes exceeds limit {}", actual, limit)
            }
            Self::CircuitOpen { failures } => {
                write!(f, "circuit breaker open after {} failures", failures)
            }
            Self::ConcurrencyLimit => write!(f, "concurrent AI request limit reached"),
            Self::TurnsExceeded { limit } => {
                write!(f, "connection exceeded {} AI turns", limit)
            }
        }
    }
}

impl std::error::Error for BudgetExceeded {}

/// Truncates a prompt to fit within the byte budget.
/// Always includes the final payload segment even if truncated.
pub fn truncate_prompt(prompt: &str, max_bytes: usize) -> String {
    if prompt.len() <= max_bytes {
        return prompt.to_string();
    }
    // Keep the tail of the prompt (most recent payload data is most relevant)
    let start = prompt.len().saturating_sub(max_bytes);
    format!("[truncated]{}", &prompt[start..])
}

/// Truncates a response to fit within the byte budget.
pub fn truncate_response(response: &str, max_bytes: usize) -> String {
    if response.len() <= max_bytes {
        return response.to_string();
    }
    // Find a valid UTF-8 char boundary at or before max_bytes
    let mut end = max_bytes;
    while end > 0 && !response.is_char_boundary(end) {
        end -= 1;
    }
    response[..end].to_string()
}

/// Circuit breaker for provider failures. Opens after `max_failures` consecutive
/// failures and resets after a cooldown period.
pub struct AiCircuitBreaker {
    failures: AtomicUsize,
    max_failures: usize,
    /// When the circuit last opened (epoch secs). 0 = closed.
    opened_at: RwLock<u64>,
    cooldown_secs: u64,
}

impl AiCircuitBreaker {
    pub fn new(max_failures: usize, cooldown_secs: u64) -> Self {
        Self {
            failures: AtomicUsize::new(0),
            max_failures,
            opened_at: RwLock::new(0),
            cooldown_secs,
        }
    }

    pub fn from_config(config: &AiBudgetConfig) -> Self {
        Self::new(config.max_provider_failures, 60)
    }

    /// Returns true if the circuit is open (requests should be rejected).
    pub fn is_open(&self) -> bool {
        let failures = self.failures.load(Ordering::Relaxed);
        if failures < self.max_failures {
            return false;
        }
        let opened = *self.opened_at.read();
        if opened == 0 {
            return true;
        }
        let now = synvoid_utils::safe_unix_timestamp();
        now.saturating_sub(opened) < self.cooldown_secs
    }

    /// Record a successful call. Resets failure count.
    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        *self.opened_at.write() = 0;
    }

    /// Record a failure. Opens circuit if threshold reached.
    pub fn record_failure(&self) {
        let prev = self.failures.fetch_add(1, Ordering::Relaxed);
        if prev + 1 >= self.max_failures {
            let mut opened = self.opened_at.write();
            if *opened == 0 {
                *opened = synvoid_utils::safe_unix_timestamp();
                tracing::warn!(
                    failures = prev + 1,
                    max = self.max_failures,
                    "AI provider circuit breaker opened"
                );
            }
        }
    }

    pub fn failure_count(&self) -> usize {
        self.failures.load(Ordering::Relaxed)
    }
}

/// Semaphore-based concurrent request limiter.
pub struct AiConcurrencyLimiter {
    semaphore: Arc<Semaphore>,
    active: Arc<AtomicUsize>,
}

impl AiConcurrencyLimiter {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn from_config(config: &AiBudgetConfig) -> Self {
        Self::new(config.max_concurrent_requests)
    }

    /// Try to acquire a permit. Returns None if at capacity.
    pub fn try_acquire(&self) -> Option<AiConcurrencyPermit> {
        let permit = self.semaphore.clone().try_acquire_owned().ok()?;
        self.active.fetch_add(1, Ordering::Relaxed);
        Some(AiConcurrencyPermit {
            _permit: permit,
            active: self.active.clone(),
        })
    }

    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
}

/// RAII permit that decrements active count on drop.
pub struct AiConcurrencyPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    active: Arc<AtomicUsize>,
}

impl Drop for AiConcurrencyPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Generic protocol-appropriate fallback response. Never leaks provider details.
pub fn fallback_response(protocol: &str) -> Vec<u8> {
    match protocol {
        "ssh" => b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n".to_vec(),
        "http" => b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
        "mysql" => vec![
            0x0a, 0x00, 0x00, 0x01, 0xff, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        "redis" => b"+OK\r\n".to_vec(),
        "ftp" => b"220 (vsFTPd 3.0.3)\r\n".to_vec(),
        "smtp" => b"220 mail.example.com ESMTP Postfix\r\n".to_vec(),
        "postgresql" => vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f],
        "smb" => vec![0x00, 0x00, 0x00, 0x85],
        "rdp" => vec![
            0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        "vnc" => b"RFB 003.008\n".to_vec(),
        _ => b"+OK\r\n".to_vec(),
    }
}

/// Per-connection turn counter. Tracks how many AI turns have been used.
pub struct AiTurnCounter {
    count: AtomicUsize,
    max_turns: usize,
}

impl AiTurnCounter {
    pub fn new(max_turns: usize) -> Self {
        Self {
            count: AtomicUsize::new(0),
            max_turns,
        }
    }

    /// Increment and check if within budget. Returns false if exceeded.
    pub fn try_increment(&self) -> bool {
        let prev = self.count.fetch_add(1, Ordering::Relaxed);
        prev < self.max_turns
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn remaining(&self) -> usize {
        self.max_turns
            .saturating_sub(self.count.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_prompt_within_budget() {
        let prompt = "short prompt";
        assert_eq!(truncate_prompt(prompt, 4096), "short prompt");
    }

    #[test]
    fn test_truncate_prompt_exceeds_budget() {
        let prompt = "a".repeat(5000);
        let result = truncate_prompt(&prompt, 4096);
        assert!(result.starts_with("[truncated]"));
        assert!(result.len() <= 4096 + "[truncated]".len());
    }

    #[test]
    fn test_truncate_response_within_budget() {
        let response = "short";
        assert_eq!(truncate_response(response, 2048), "short");
    }

    #[test]
    fn test_truncate_response_exceeds_budget() {
        let response = "x".repeat(3000);
        let result = truncate_response(&response, 2048);
        assert_eq!(result.len(), 2048);
        assert!(result.is_char_boundary(result.len()));
    }

    #[test]
    fn test_circuit_breaker_stays_closed_below_threshold() {
        let cb = AiCircuitBreaker::new(3, 60);
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_open());
    }

    #[test]
    fn test_circuit_breaker_opens_at_threshold() {
        let cb = AiCircuitBreaker::new(3, 60);
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open());
    }

    #[test]
    fn test_circuit_breaker_resets_on_success() {
        let cb = AiCircuitBreaker::new(3, 60);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert!(!cb.is_open());
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_concurrency_limiter_within_limit() {
        let limiter = AiConcurrencyLimiter::new(2);
        let p1 = limiter.try_acquire();
        assert!(p1.is_some());
        let p2 = limiter.try_acquire();
        assert!(p2.is_some());
        assert_eq!(limiter.active_count(), 2);
    }

    #[test]
    fn test_concurrency_limiter_exceeds_limit() {
        let limiter = AiConcurrencyLimiter::new(1);
        let _p1 = limiter.try_acquire();
        let p2 = limiter.try_acquire();
        assert!(p2.is_none());
    }

    #[test]
    fn test_concurrency_limiter_releases_on_drop() {
        let limiter = AiConcurrencyLimiter::new(1);
        {
            let _p1 = limiter.try_acquire();
            assert_eq!(limiter.active_count(), 1);
        }
        assert_eq!(limiter.active_count(), 0);
        let p2 = limiter.try_acquire();
        assert!(p2.is_some());
    }

    #[test]
    fn test_turn_counter_within_budget() {
        let counter = AiTurnCounter::new(3);
        assert!(counter.try_increment());
        assert!(counter.try_increment());
        assert!(counter.try_increment());
        assert_eq!(counter.count(), 3);
        assert_eq!(counter.remaining(), 0);
    }

    #[test]
    fn test_turn_counter_exceeds_budget() {
        let counter = AiTurnCounter::new(2);
        assert!(counter.try_increment());
        assert!(counter.try_increment());
        assert!(!counter.try_increment());
        assert_eq!(counter.count(), 3);
    }

    #[test]
    fn test_fallback_response_returns_protocol_data() {
        let ssh = fallback_response("ssh");
        assert!(ssh.starts_with(b"SSH-2.0"));
        let http = fallback_response("http");
        assert!(http.starts_with(b"HTTP/1.1"));
        let unknown = fallback_response("bogus");
        assert!(!unknown.is_empty());
    }
}
