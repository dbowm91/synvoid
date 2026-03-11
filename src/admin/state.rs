use super::ws::broadcaster::Broadcaster;
use crate::config::ConfigManager;
use crate::waf::{ProbeTracker, SuspiciousWordTracker, ThreatLevelManager, UpstreamErrorTracker};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AdminState {
    pub config: Arc<RwLock<ConfigManager>>,
    pub admin_token: String,
    pub metrics_broadcaster: Arc<Broadcaster>,
    pub logs_broadcaster: Arc<Broadcaster>,
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
}

impl AdminState {
    pub fn new(config: Arc<RwLock<ConfigManager>>, admin_token: String) -> Self {
        Self {
            config,
            admin_token,
            metrics_broadcaster: Arc::new(Broadcaster::new(100)),
            logs_broadcaster: Arc::new(Broadcaster::new(1000)),
            probe_tracker: None,
            suspicious_word_tracker: None,
            upstream_error_tracker: None,
            threat_level_manager: None,
        }
    }

    pub fn with_probe_tracker(mut self, tracker: Option<Arc<ProbeTracker>>) -> Self {
        self.probe_tracker = tracker;
        self
    }

    pub fn with_suspicious_word_tracker(
        mut self,
        tracker: Option<Arc<SuspiciousWordTracker>>,
    ) -> Self {
        self.suspicious_word_tracker = tracker;
        self
    }

    pub fn with_upstream_error_tracker(
        mut self,
        tracker: Option<Arc<UpstreamErrorTracker>>,
    ) -> Self {
        self.upstream_error_tracker = tracker;
        self
    }

    pub fn with_threat_level_manager(mut self, manager: Option<Arc<ThreatLevelManager>>) -> Self {
        self.threat_level_manager = manager;
        self
    }
}
