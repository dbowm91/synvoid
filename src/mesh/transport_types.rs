use std::sync::Arc;
use std::time::Instant;

use quinn::Connection;

use crate::waf::ratelimit::core::AtomicSlidingWindow;

pub struct MeshGlobalRateLimiter {
    per_second: AtomicSlidingWindow,
    per_minute: AtomicSlidingWindow,
    limit_per_second: u64,
    limit_per_minute: u64,
}

impl MeshGlobalRateLimiter {
    pub fn new(messages_per_second: usize, messages_per_minute: usize) -> Self {
        Self {
            per_second: AtomicSlidingWindow::new(1, 10),
            per_minute: AtomicSlidingWindow::new(60, 60),
            limit_per_second: messages_per_second.max(1) as u64,
            limit_per_minute: messages_per_minute.max(1) as u64,
        }
    }

    pub(crate) fn check(&self) -> GlobalRateLimitCheck {
        let now_ms = crate::utils::safe_unix_duration().as_millis() as u64;

        let current_per_second = self.per_second.get_count(now_ms);
        let current_per_minute = self.per_minute.get_count(now_ms);

        GlobalRateLimitCheck {
            current_per_second,
            current_per_minute,
            exceeded_per_second: current_per_second > self.limit_per_second,
            exceeded_per_minute: current_per_minute > self.limit_per_minute,
        }
    }

    pub fn record(&self) {
        let now_ms = crate::utils::safe_unix_duration().as_millis() as u64;

        self.per_second.increment(now_ms);
        self.per_minute.increment(now_ms);
    }
}

#[allow(dead_code)]
pub(crate) struct GlobalRateLimitCheck {
    pub current_per_second: u64,
    pub current_per_minute: u64,
    pub exceeded_per_second: bool,
    pub exceeded_per_minute: bool,
}

#[derive(Clone)]
pub struct MeshPeerConnection {
    pub node_id: String,
    pub address: String,
    pub connection: Connection,
    pub session_id: String,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub role: crate::mesh::config::MeshNodeRole,
    pub upstreams: Vec<String>,
    pub is_trusted: bool,
    pub replay_protection: Arc<tokio::sync::RwLock<crate::mesh::protocol::ReplayProtection>>,
}
