pub mod bootstrap;
pub mod daemon;
pub mod master;
pub mod worker;

use std::sync::Arc;

use tokio::sync::{broadcast, RwLock};

use crate::block_store::BlockStore;
use crate::config::ConfigManager;
use crate::waf::{
    ProbeTracker, RuleFeedManagerForWaf, SuspiciousWordTracker, ThreatLevelManager,
    UpstreamErrorTracker,
};

#[derive(Clone)]
pub struct MasterState {
    pub config: Arc<RwLock<ConfigManager>>,
    pub shutdown_tx: broadcast::Sender<()>,
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
    pub rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    #[allow(dead_code)] // Reserved for master-level IP blocking
    pub block_store: Arc<BlockStore>,
    pub mesh_transport: Option<Arc<crate::mesh::transport::MeshTransport>>,
}

#[derive(Clone)]
pub struct MasterStateTrackers {
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
    pub rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
}

impl MasterState {
    pub fn new(
        config: Arc<RwLock<ConfigManager>>,
        trackers: MasterStateTrackers,
        block_store: Arc<BlockStore>,
        mesh_transport: Option<Arc<crate::mesh::transport::MeshTransport>>,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config,
            shutdown_tx,
            probe_tracker: trackers.probe_tracker,
            suspicious_word_tracker: trackers.suspicious_word_tracker,
            upstream_error_tracker: trackers.upstream_error_tracker,
            threat_level_manager: trackers.threat_level_manager,
            rule_feed_manager: trackers.rule_feed_manager,
            block_store,
            mesh_transport,
        }
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}
