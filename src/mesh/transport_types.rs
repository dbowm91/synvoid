use std::time::Instant;

use quinn::Connection;

use crate::waf::ratelimit::core::AtomicSlidingWindow;

pub struct MeshGlobalRateLimiter {
    per_second: AtomicSlidingWindow,
    per_minute: AtomicSlidingWindow,
}

impl MeshGlobalRateLimiter {
    pub fn new(_messages_per_second: usize, _messages_per_minute: usize) -> Self {
        Self {
            per_second: AtomicSlidingWindow::new(1, 10),
            per_minute: AtomicSlidingWindow::new(60, 60),
        }
    }

    pub(crate) fn check(&self) -> GlobalRateLimitCheck {
        let now_ms = crate::utils::safe_unix_duration().as_millis() as u64;

        GlobalRateLimitCheck {
            current_per_second: self.per_second.get_count(now_ms),
            current_per_minute: self.per_minute.get_count(now_ms),
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
}
