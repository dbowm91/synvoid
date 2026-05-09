use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::block_store::BlockStore;
use crate::config::ConfigManager;
use crate::waf::{
    ProbeTracker, RuleFeedManagerForWaf, SuspiciousWordTracker, ThreatLevelManager,
    UpstreamErrorTracker,
};

#[cfg(feature = "mesh")]
use crate::waf::YaraRulesManager;
#[cfg(feature = "mesh")]
use crate::mesh::threat_intel::ThreatIntelligenceManager;

#[derive(Clone)]
pub struct SupervisorState {
    pub config: Arc<RwLock<ConfigManager>>,
    pub shutdown_tx: broadcast::Sender<()>,
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
    pub rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    #[cfg(feature = "mesh")]
    pub threat_intel_manager: Option<Arc<ThreatIntelligenceManager>>,
    #[cfg(feature = "mesh")]
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    pub block_store: Arc<BlockStore>,
    #[cfg(feature = "mesh")]
    pub mesh_transport_manager: Option<Arc<crate::mesh::transports::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub org_key_manager: Option<Arc<crate::mesh::org_key_manager::OrgKeyManager>>,
}

#[derive(Clone, Default)]
pub struct SupervisorStateTrackers {
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
    pub rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    #[cfg(feature = "mesh")]
    pub threat_intel_manager: Option<Arc<ThreatIntelligenceManager>>,
    #[cfg(feature = "mesh")]
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport_manager: Option<Arc<crate::mesh::transports::MeshTransportManager>>,
}

impl SupervisorState {
    pub fn new(
        config: Arc<RwLock<ConfigManager>>,
        trackers: SupervisorStateTrackers,
        block_store: Arc<BlockStore>,
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
            #[cfg(feature = "mesh")]
            threat_intel_manager: trackers.threat_intel_manager,
            #[cfg(feature = "mesh")]
            yara_rules: trackers.yara_rules,
            block_store,
            #[cfg(feature = "mesh")]
            mesh_transport_manager: trackers.mesh_transport_manager,
            #[cfg(feature = "mesh")]
            org_key_manager: None,
        }
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}
