//! Synchronous replay protection (value semantics, injectable clock).
//!
//! Copied from `synvoid-mesh/src/mesh/protocol.rs::ReplayProtection` with the
//! `synvoid_utils::safe_unix_timestamp` dependency replaced by
//! `crate::time::current_unix_timestamp` plus an injectable `check_and_add_at`
/// entry point for deterministic tests.
use std::collections::HashSet;

use crate::constants::{MAX_REPLAY_CACHE_SIZE, REPLAY_WINDOW_SECS};
use crate::time::current_unix_timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayResult {
    Valid,
    ReplayDetected,
    ExpiredTimestamp,
    FutureTimestamp,
}

#[derive(Clone, Debug)]
pub struct ReplayProtection {
    seen_nonces: HashSet<String>,
}

impl ReplayProtection {
    pub fn new() -> Self {
        Self {
            seen_nonces: HashSet::new(),
        }
    }

    pub fn check_and_add(&mut self, nonce: &str, timestamp: u64) -> ReplayResult {
        self.check_and_add_at(nonce, timestamp, current_unix_timestamp())
    }

    /// Deterministic entry point: `now` is injected by the caller.
    pub fn check_and_add_at(&mut self, nonce: &str, timestamp: u64, now: u64) -> ReplayResult {
        if timestamp > now + 60 {
            return ReplayResult::FutureTimestamp;
        }

        if now.saturating_sub(timestamp) > REPLAY_WINDOW_SECS {
            return ReplayResult::ExpiredTimestamp;
        }

        let nonce_key = format!("{}:{}", timestamp, nonce);
        if self.seen_nonces.contains(&nonce_key) {
            return ReplayResult::ReplayDetected;
        }

        if self.seen_nonces.len() >= MAX_REPLAY_CACHE_SIZE {
            let old_count = self.seen_nonces.len() / 4;
            let to_remove: Vec<_> = self.seen_nonces.iter().take(old_count).cloned().collect();
            for key in to_remove {
                self.seen_nonces.remove(&key);
            }
        }

        self.seen_nonces.insert(nonce_key);
        ReplayResult::Valid
    }

    pub fn clear(&mut self) {
        self.seen_nonces.clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.seen_nonces.len()
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}
