#![allow(dead_code)] // Reserved for future rate limiting integration

use crate::mesh::transport::{MeshTransport, PEER_RATE_LIMIT_WINDOW_SECS};
use std::time::{Duration, Instant};

impl MeshTransport {
    pub(crate) fn verify_auth_token(&self, node_id: &str, token: &str) -> bool {
        let keys = self.auth_keys.read();
        if let Some(expected_key) = keys.get(node_id) {
            return expected_key.as_slice() == token.as_bytes();
        }
        if keys.is_empty() {
            return true;
        }
        false
    }

    pub(crate) fn record_auth_failure(&self, node_id: &str) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.connection.auth_failure_window_secs);
        let max_failures = self.config.connection.max_auth_failures;

        let mut failures = self.auth_failures.write();
        let node_failures = failures.entry(node_id.to_string()).or_default();

        node_failures.retain(|t| now.duration_since(*t) < window);

        if node_failures.len() >= max_failures {
            tracing::error!(
                "Node {} blocked due to repeated authentication failures",
                node_id
            );
            node_failures.push(now);
        } else {
            node_failures.push(now);
            tracing::warn!(
                "Authentication failure for node {} ({} failures)",
                node_id,
                node_failures.len()
            );
        }
    }

    pub(crate) fn is_node_blocked(&self, node_id: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.connection.auth_failure_window_secs);
        let max_failures = self.config.connection.max_auth_failures;

        let failures = self.auth_failures.read();
        if let Some(node_failures) = failures.get(node_id) {
            let recent_failures: Vec<_> = node_failures
                .iter()
                .filter(|t| now.duration_since(**t) < window)
                .collect();
            return recent_failures.len() >= max_failures;
        }

        false
    }

    pub(crate) fn clear_auth_failures(&self, node_id: &str) {
        let mut failures = self.auth_failures.write();
        failures.remove(node_id);
    }

    pub(crate) fn check_peer_rate_limit(&self, peer_id: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(PEER_RATE_LIMIT_WINDOW_SECS);

        let max_rate = self.config.routing.mesh_messages_per_sec * 60;

        let mut times = self.peer_message_times.write();
        let peer_times = times.entry(peer_id.to_string()).or_default();

        peer_times.retain(|t| now.duration_since(*t) < window);

        if peer_times.len() >= max_rate {
            tracing::warn!(
                "Peer {} rate limit exceeded: {} messages in {}s (limit: {})",
                peer_id,
                peer_times.len(),
                PEER_RATE_LIMIT_WINDOW_SECS,
                max_rate
            );
            return false;
        }

        peer_times.push(now);
        true
    }

    pub(crate) fn get_auth_failure_count(&self, node_id: &str) -> usize {
        let failures = self.auth_failures.read();
        failures.get(node_id).map(|v| v.len()).unwrap_or(0)
    }

    pub(crate) fn get_peer_message_count(&self, peer_id: &str) -> usize {
        let times = self.peer_message_times.read();
        times.get(peer_id).map(|v| v.len()).unwrap_or(0)
    }

    pub(crate) fn cleanup_rate_limit_state(&self) {
        let now = Instant::now();

        {
            let mut failures = self.auth_failures.write();
            let window = Duration::from_secs(self.config.connection.auth_failure_window_secs);
            for (_, v) in failures.iter_mut() {
                v.retain(|t| now.duration_since(*t) < window);
            }
            failures.retain(|_, v| !v.is_empty());
        }

        {
            let mut times = self.peer_message_times.write();
            let window = Duration::from_secs(PEER_RATE_LIMIT_WINDOW_SECS);
            for (_, v) in times.iter_mut() {
                v.retain(|t| now.duration_since(*t) < window);
            }
            times.retain(|_, v| !v.is_empty());
        }
    }
}
