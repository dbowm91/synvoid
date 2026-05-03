pub mod bootstrap;
pub mod daemon;
pub mod master;
pub mod worker;

use std::sync::Arc;

use tokio::sync::{broadcast, RwLock};

use crate::block_store::BlockStore;
use crate::config::ConfigManager;
#[cfg(feature = "mesh")]
use crate::waf::YaraRulesManager;
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
    #[cfg(feature = "mesh")]
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    pub block_store: Arc<BlockStore>,
    #[cfg(feature = "mesh")]
    pub mesh_transport: Option<Arc<crate::mesh::transport::MeshTransport>>,
    #[cfg(feature = "mesh")]
    pub org_key_manager: Option<Arc<crate::mesh::org_key_manager::OrgKeyManager>>,
}

#[derive(Clone)]
pub struct MasterStateTrackers {
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
    pub rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    #[cfg(feature = "mesh")]
    pub yara_rules: Option<Arc<YaraRulesManager>>,
}

impl MasterState {
    #[cfg(feature = "mesh")]
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
            yara_rules: trackers.yara_rules,
            block_store,
            mesh_transport: mesh_transport.clone(),
            org_key_manager: mesh_transport.map(|m| m.org_key_manager.clone()),
        }
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}
