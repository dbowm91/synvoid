//! Bounded password-crypto executor (Phase 43, Workstream A).
//!
//! CPU-hard bcrypt work must never run directly on a Tokio core executor
//! thread and must never be scheduled without an explicit concurrency bound.
//! [`PasswordCrypto`] acquires a semaphore permit *before* scheduling work
//! with [`tokio::task::spawn_blocking`] and holds the permit until the
//! blocking operation completes. Overload fails closed with
//! [`PasswordCryptoError::Busy`]; no caller may authenticate on overload.
//!
//! Never logs plaintext passwords/tokens. Password/hash inputs are moved
//! into the blocking closure and dropped there.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Conservative default bound for concurrent bcrypt operations.
///
/// bcrypt at cost 12 saturates a core for ~200-400ms. Four permits keep
/// login/user-creation throughput usable on small hosts without letting
/// password crypto starve the Tokio blocking pool or the CPU-worker
/// expectations. Internal constant on purpose (Phase 43): no operator knob
/// until benchmark evidence demands tuning.
pub const DEFAULT_PASSWORD_CRYPTO_CONCURRENCY: usize = 4;

/// How long a caller waits for a crypto permit before failing closed.
pub const DEFAULT_PASSWORD_CRYPTO_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);

/// Bcrypt cost used for new hashes. Matches the previous `DEFAULT_COST` (12)
/// so existing hashes keep verifying and new hashes keep the same format.
pub const PASSWORD_BCRYPT_COST: u32 = 12;

/// Dummy hash used for constant-work verification of unknown users.
/// Same value as the historic `DUMMY_PASSWORD_HASH` so timing behavior is
/// unchanged; it is public only for tests that assert single-verify paths.
pub const DUMMY_PASSWORD_HASH: &str =
    "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzS.xJ5mW6";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordCryptoError {
    /// All permits in use past the acquire timeout. Caller must fail closed.
    Busy,
    /// Blocking task failed to join.
    Join,
    /// Bcrypt hashing backend failure.
    Hash,
    /// Bcrypt verification backend failure (malformed hash, backend error).
    /// Callers map this to invalid credentials (fail closed).
    Verify,
}

impl std::fmt::Display for PasswordCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => write!(f, "password crypto backend busy"),
            Self::Join => write!(f, "password crypto task failed"),
            Self::Hash => write!(f, "password hashing failed"),
            Self::Verify => write!(f, "password verification failed"),
        }
    }
}

impl std::error::Error for PasswordCryptoError {}

#[derive(Debug, Clone)]
pub struct PasswordCrypto {
    permits: Arc<Semaphore>,
    acquire_timeout: Duration,
    cost: u32,
    max_concurrent: usize,
}

impl Default for PasswordCrypto {
    fn default() -> Self {
        Self::new(
            DEFAULT_PASSWORD_CRYPTO_CONCURRENCY,
            DEFAULT_PASSWORD_CRYPTO_ACQUIRE_TIMEOUT,
            PASSWORD_BCRYPT_COST,
        )
    }
}

impl PasswordCrypto {
    pub fn new(max_concurrent: usize, acquire_timeout: Duration, cost: u32) -> Self {
        let max = max_concurrent.max(1);
        Self {
            permits: Arc::new(Semaphore::new(max)),
            acquire_timeout,
            cost,
            max_concurrent: max,
        }
    }

    /// Test hook: bound of one + tiny timeout to deterministically trigger overload.
    #[cfg(test)]
    pub fn single_permit_for_tests() -> Self {
        Self::new(1, Duration::from_millis(50), 4)
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    async fn acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit, PasswordCryptoError> {
        let permits = Arc::clone(&self.permits);
        let timeout = self.acquire_timeout;
        let acquire = async move { permits.acquire_owned().await };
        match tokio::time::timeout(timeout, acquire).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(PasswordCryptoError::Join),
            Err(_) => Err(PasswordCryptoError::Busy),
        }
    }

    /// Hash a password without blocking a Tokio core thread.
    pub async fn hash(&self, password: String) -> Result<String, PasswordCryptoError> {
        let _permit = self.acquire().await?;
        let cost = self.cost;
        let handle = tokio::task::spawn_blocking(move || {
            // `password` is dropped here; never logged.
            bcrypt::hash(password, cost).map_err(|_| PasswordCryptoError::Hash)
        });
        let result = handle.await.map_err(|_| PasswordCryptoError::Join)?;
        // `_permit` held across the await: concurrency stays bounded.
        drop(_permit);
        result
    }

    /// Verify a password against a bcrypt hash without blocking a core thread.
    ///
    /// Returns `Ok(true/false)` for completed verifications. Bcrypt-internal
    /// errors (e.g. malformed hash) surface as `Err(Verify)` so callers can
    /// fail closed without treating them as overload.
    pub async fn verify(
        &self,
        password: String,
        hash: String,
    ) -> Result<bool, PasswordCryptoError> {
        let _permit = self.acquire().await?;
        let handle = tokio::task::spawn_blocking(move || {
            bcrypt::verify(password, hash.as_str()).map_err(|_| PasswordCryptoError::Verify)
        });
        let result = handle.await.map_err(|_| PasswordCryptoError::Join)?;
        drop(_permit);
        result
    }

    /// Constant-work verification for unknown users / missing tokens.
    /// Exactly one bounded bcrypt; callers add minimum-delay padding
    /// themselves without a second expensive verify.
    pub async fn verify_dummy(&self, password: String) -> Result<bool, PasswordCryptoError> {
        self.verify(password, DUMMY_PASSWORD_HASH.to_string()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn concurrency_never_exceeds_permits() {
        let crypto = Arc::new(PasswordCrypto::new(2, Duration::from_secs(10), 4));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = Arc::clone(&crypto);
            let in_flight = Arc::clone(&in_flight);
            let max_seen = Arc::clone(&max_seen);
            handles.push(tokio::spawn(async move {
                let _permit = c.acquire().await.unwrap();
                let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(cur, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(max_seen.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test]
    async fn overload_fails_closed() {
        let crypto = PasswordCrypto::new(1, Duration::from_millis(50), 4);
        let _held = crypto.acquire().await.expect("first permit");
        let err = crypto.acquire().await.expect_err("second must be busy");
        assert_eq!(err, PasswordCryptoError::Busy);
    }

    #[tokio::test]
    async fn executor_progress_while_crypto_saturated() {
        // Saturate the single permit with a slow holder, then prove the
        // async executor still makes progress (counter advances) while
        // a verify fails closed with Busy instead of hanging.
        let crypto = Arc::new(PasswordCrypto::new(1, Duration::from_millis(50), 4));
        let _held = crypto.acquire().await.expect("hold permit");
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter);
        let ticker = tokio::spawn(async move {
            for _ in 0..10 {
                c2.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let err = crypto
            .verify("pw".to_string(), DUMMY_PASSWORD_HASH.to_string())
            .await
            .expect_err("saturated verify must fail closed");
        assert_eq!(err, PasswordCryptoError::Busy);
        ticker.await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }
}
