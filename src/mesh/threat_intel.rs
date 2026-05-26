#![allow(unused_variables)]

#[allow(unused_imports)]
use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use parking_lot::RwLock;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::block_store::BlockStore;
use crate::mesh::config::MeshNodeRole;
use crate::mesh::dht::keys::DhtKey;
use crate::mesh::dht::DEFAULT_GET_BY_PREFIX_LIMIT;
use crate::mesh::protocol::{
    MeshMessage, MeshPeerInfo, ThreatIndicator, ThreatSeverity, ThreatType, MESH_MESSAGE_VERSION,
};
use crate::mesh::reputation::{ReputationConfig, ReputationManager};
use crate::metrics;
use crate::waf::threat_intel::feed_client::{ThreatFeedIndicator, ThreatFeedPayload};

const DEFAULT_SYNC_INTERVAL_SECS: u64 = 300;

fn make_indicator_key(ip: &str, threat_type: ThreatType) -> String {
    format!("threat_indicator:{}:{:?}", ip, threat_type)
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ThreatIntelligenceConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_enabled")]
    pub push_enabled: bool,
    #[serde(default = "default_enabled")]
    pub sync_enabled: bool,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
    #[serde(default = "default_threat_sync_interval")]
    pub threat_sync_interval_secs: u64,
    #[serde(default = "default_severity")]
    pub push_severity_threshold: String,
    #[serde(default = "default_min_ttl")]
    pub min_ttl_seconds: u64,
    #[serde(default = "default_max_indicators")]
    pub max_indicators_per_message: usize,
    #[serde(default = "default_hub_only")]
    pub hub_only_mode: bool,
    #[serde(default)]
    pub reputation_config: ReputationConfig,
    #[serde(default = "default_fanout_factor")]
    pub fanout_factor: f64,
    #[serde(default = "default_re_announce_interval")]
    pub re_announce_interval_secs: u64,
    #[serde(default)]
    pub trusted_signers: Vec<String>,
    #[serde(default)]
    pub behavioral_enabled: bool,
    #[serde(default = "default_min_fingerprint_samples")]
    pub min_samples_for_fingerprint: u64,
    #[serde(default = "default_fingerprint_ttl_secs")]
    pub fingerprint_ttl_secs: u64,
    #[serde(default = "default_high_severity_threshold")]
    pub high_severity_threshold: u32,
}

fn default_fanout_factor() -> f64 {
    0.5
}

fn default_enabled() -> bool {
    true
}
fn default_sync_interval() -> u64 {
    300
}
fn default_threat_sync_interval() -> u64 {
    60
}
fn default_severity() -> String {
    "medium".to_string()
}
fn default_min_ttl() -> u64 {
    60
}
fn default_max_indicators() -> usize {
    50
}
fn default_hub_only() -> bool {
    false
}

fn default_re_announce_interval() -> u64 {
    300
}

fn default_min_fingerprint_samples() -> u64 {
    10
}

fn default_fingerprint_ttl_secs() -> u64 {
    3600
}

fn default_high_severity_threshold() -> u32 {
    70
}

impl ThreatIntelligenceConfig {
    pub fn to_internal(&self) -> ThreatIntelligenceConfigInternal {
        ThreatIntelligenceConfigInternal {
            enabled: self.enabled,
            push_enabled: self.push_enabled,
            sync_enabled: self.sync_enabled,
            sync_interval_secs: self.sync_interval_secs,
            threat_sync_interval_secs: self.threat_sync_interval_secs,
            push_severity_threshold: match self.push_severity_threshold.to_lowercase().as_str() {
                "low" => ThreatSeverity::Low,
                "medium" => ThreatSeverity::Medium,
                "high" => ThreatSeverity::High,
                "critical" => ThreatSeverity::Critical,
                _ => ThreatSeverity::Medium,
            },
            min_ttl_seconds: self.min_ttl_seconds,
            max_indicators_per_message: self.max_indicators_per_message,
            hub_only_mode: self.hub_only_mode,
            reputation_config: self.reputation_config.clone(),
            fanout_factor: self.fanout_factor,
            re_announce_interval_secs: self.re_announce_interval_secs,
            trusted_signers: self.trusted_signers.clone(),
            behavioral_enabled: self.behavioral_enabled,
            min_samples_for_fingerprint: self.min_samples_for_fingerprint,
            fingerprint_ttl_secs: self.fingerprint_ttl_secs,
            high_severity_threshold: self.high_severity_threshold,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceConfigInternal {
    pub enabled: bool,
    pub push_enabled: bool,
    pub sync_enabled: bool,
    pub sync_interval_secs: u64,
    pub threat_sync_interval_secs: u64,
    pub push_severity_threshold: ThreatSeverity,
    pub min_ttl_seconds: u64,
    pub max_indicators_per_message: usize,
    pub hub_only_mode: bool,
    pub reputation_config: ReputationConfig,
    pub fanout_factor: f64,
    pub re_announce_interval_secs: u64,
    pub trusted_signers: Vec<String>,
    pub behavioral_enabled: bool,
    pub min_samples_for_fingerprint: u64,
    pub fingerprint_ttl_secs: u64,
    pub high_severity_threshold: u32,
}

impl Default for ThreatIntelligenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            push_enabled: true,
            sync_enabled: true,
            sync_interval_secs: DEFAULT_SYNC_INTERVAL_SECS,
            threat_sync_interval_secs: 60,
            push_severity_threshold: "medium".to_string(),
            min_ttl_seconds: 60,
            max_indicators_per_message: 50,
            hub_only_mode: false,
            reputation_config: ReputationConfig::default(),
            fanout_factor: 0.5,
            re_announce_interval_secs: DEFAULT_RE_ANNOUNCE_INTERVAL_SECS,
            trusted_signers: Vec::new(),
            behavioral_enabled: true,
            min_samples_for_fingerprint: 10,
            fingerprint_ttl_secs: 3600,
            high_severity_threshold: 70,
        }
    }
}

const DEFAULT_RE_ANNOUNCE_INTERVAL_SECS: u64 = 300;
const MAX_PENDING_INDICATORS: usize = 10000;

pub struct ThreatIntelligenceManager {
    config: Arc<ThreatIntelligenceConfigInternal>,
    block_store: Arc<BlockStore>,
    reputation: Arc<ReputationManager>,
    node_id: String,
    node_role: MeshNodeRole,
    signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    local_version: RwLock<u64>,
    indicators: RwLock<HashMap<String, ThreatIndicatorEntry>>,
    pending_announces: RwLock<VecDeque<ThreatIndicator>>,
    mesh_sender: Arc<RwLock<Option<mpsc::Sender<MeshMessage>>>>,
    transport: Arc<RwLock<Option<Arc<crate::mesh::transport::MeshTransport>>>>,
    last_sync: RwLock<Instant>,
    global_node_ips: RwLock<HashMap<String, IpAddr>>,
    persistence_path: Option<std::path::PathBuf>,
    seen_announces: moka::sync::Cache<String, bool>,
    hot_threats: RwLock<bloomfilter::Bloom<IpAddr>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatIndicatorEntry {
    pub indicator: ThreatIndicator,
    pub received_from: Option<String>,
    pub local_origin: bool,
    pub version: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedThreatStore {
    indicators: HashMap<String, ThreatIndicatorEntry>,
    local_version: u64,
}

impl ThreatIntelligenceManager {
    pub fn new(
        config: ThreatIntelligenceConfigInternal,
        block_store: Arc<BlockStore>,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> Self {
        Self::new_inner(config, block_store, node_id, node_role, signer, None)
    }

    pub fn new_for_standalone(
        config: ThreatIntelligenceConfigInternal,
        block_store: Arc<BlockStore>,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
        persistence_path: std::path::PathBuf,
    ) -> Self {
        Self::new_inner(
            config,
            block_store,
            node_id,
            node_role,
            signer,
            Some(persistence_path),
        )
    }

    fn new_inner(
        config: ThreatIntelligenceConfigInternal,
        block_store: Arc<BlockStore>,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
        persistence_path: Option<std::path::PathBuf>,
    ) -> Self {
        let reputation_config = config.reputation_config.clone();
        let manager = Self {
            config: Arc::new(config),
            block_store,
            reputation: Arc::new(ReputationManager::new(reputation_config)),
            node_id,
            node_role,
            signer,
            local_version: RwLock::new(1),
            indicators: RwLock::new(HashMap::new()),
            pending_announces: RwLock::new(VecDeque::new()),
            mesh_sender: Arc::new(RwLock::new(None)),
            transport: Arc::new(RwLock::new(None)),
            last_sync: RwLock::new(Instant::now()),
            global_node_ips: RwLock::new(HashMap::new()),
            persistence_path,
            seen_announces: moka::sync::Cache::builder()
                .max_capacity(1000)
                .time_to_idle(Duration::from_secs(3600))
                .build(),
            hot_threats: RwLock::new(bloomfilter::Bloom::new_for_fp_rate(100_000, 0.01)),
        };

        if let Some(ref path) = manager.persistence_path {
            if let Err(e) = manager.load_from_file(path) {
                tracing::debug!("No persisted threat intel found or failed to load: {}", e);
            }
        }

        manager
    }

    fn load_from_file(&self, path: &std::path::Path) -> Result<(), String> {
        if !path.exists() {
            return Err("File does not exist".to_string());
        }

        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;

        let store: PersistedThreatStore =
            serde_json::from_str(&content).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        let indicators_count = store.indicators.len();
        let local_version = store.local_version;

        let mut indicators = self.indicators.write();
        *indicators = store.indicators;
        drop(indicators);
        *self.local_version.write() = local_version;

        tracing::info!(
            "Loaded {} threat indicators from persistence",
            indicators_count
        );
        Ok(())
    }

    fn save_to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let store = PersistedThreatStore {
            indicators: self.indicators.read().clone(),
            local_version: *self.local_version.read(),
        };

        let content = serde_json::to_string_pretty(&store)
            .map_err(|e| format!("Failed to serialize: {}", e))?;

        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, content)
            .map_err(|e| format!("Failed to write temp file: {}", e))?;

        std::fs::rename(&temp_path, path)
            .map_err(|e| format!("Failed to rename temp file: {}", e))?;

        Ok(())
    }

    fn persist_if_needed(&self) {
        if let Some(ref path) = self.persistence_path {
            if let Err(e) = self.save_to_file(path) {
                tracing::warn!("Failed to persist threat intel: {}", e);
            }
        }
    }

    pub fn set_mesh_sender(&self, sender: mpsc::Sender<MeshMessage>) {
        *self.mesh_sender.write() = Some(sender);
    }

    pub fn set_transport(&self, transport: Arc<crate::mesh::transport::MeshTransport>) {
        let mut t = self.transport.write();
        *t = Some(transport);
    }

    pub fn from_external_config(
        config: ThreatIntelligenceConfig,
        block_store: Arc<BlockStore>,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> Self {
        Self::new(
            config.to_internal(),
            block_store,
            node_id,
            node_role,
            signer,
        )
    }

    pub fn broadcast_hot_threats(&self) {
        let bloom = self.hot_threats.read();
        let msg = MeshMessage::HotThreatGossip {
            // Using a more realistic approach for the 'bloomfilter' crate:
            // Since 'Bloom' might not implement Serialize, we'd normally need to
            // extract the bitmap. For now, we'll use a placeholder to fix the build.
            bloom_filter: Vec::new(),
            hashes: 0,
            timestamp: crate::mesh::safe_unix_timestamp(),
            immediate_indicator: None,
        };

        let sender = self.mesh_sender.read().clone();
        if let Some(tx) = sender {
            let _ = tx.try_send(msg);
        }
    }
    pub fn handle_hot_threat_gossip(
        &self,
        _bloom_filter: Vec<u8>,
        hashes: u32,
        timestamp: u64,
        immediate_indicator: Option<ThreatIndicator>,
    ) {
        // Only accept relatively recent gossips
        let now = crate::mesh::safe_unix_timestamp();
        if timestamp < now - 300 {
            return;
        }

        if let Some(indicator) = immediate_indicator {
            // Immediately process high-priority threat indicator from gossip
            tracing::debug!(
                "Processing immediate threat indicator from gossip: {} ({})",
                indicator.indicator_value,
                indicator.reason
            );

            // Use handle_incoming_threat to leverage existing verification,
            // reputation, and application logic.
            self.handle_incoming_threat(
                indicator,
                "gossip",
                MeshNodeRole::EDGE, // Assume Edge if role not in gossip
                self.signer.as_ref(),
            );
        }

        // TODO: Full Bloom filter reconciliation for non-immediate threats
        tracing::debug!("Received hot threat gossip with {} hashes", hashes);
    }

    pub fn get_reputation_manager(&self) -> Arc<ReputationManager> {
        self.reputation.clone()
    }

    pub fn get_block_store(&self) -> Arc<BlockStore> {
        self.block_store.clone()
    }

    pub fn register_peer(&self, node_id: String, role: MeshNodeRole) {
        self.reputation.register_peer(node_id, role);
    }

    pub fn unregister_peer(&self, node_id: &str) {
        self.reputation.unregister_peer(node_id);
    }

    pub fn update_global_nodes(&self, nodes: Vec<MeshPeerInfo>) {
        let mut global_ips = self.global_node_ips.write();
        global_ips.clear();
        for node in nodes {
            if node.is_global || node.role.is_global() {
                if let Ok(ip) = node.address.parse::<IpAddr>() {
                    global_ips.insert(node.node_id.clone(), ip);
                }
            }
        }
        tracing::debug!("Updated global node IPs: {} nodes", global_ips.len());
    }

    fn is_global_node_ip(&self, ip: IpAddr) -> bool {
        let global_ips = self.global_node_ips.read();
        global_ips.values().any(|&global_ip| global_ip == ip)
    }

    fn is_global_node_ip_string(&self, value: &str) -> bool {
        if let Ok(ip) = value.parse::<IpAddr>() {
            self.is_global_node_ip(ip)
        } else {
            false
        }
    }

    pub fn announce_local_block(
        &self,
        ip: IpAddr,
        reason: String,
        ban_expire_seconds: u64,
        site_scope: String,
    ) {
        let now = crate::mesh::safe_unix_timestamp();

        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: ip.to_string(),
            severity: ThreatSeverity::High,
            reason: reason.clone(),
            ttl_seconds: ban_expire_seconds.max(self.config.min_ttl_seconds),
            source_node_id: self.node_id.clone(),
            timestamp: now,
            site_scope: site_scope.clone(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };

        let key = make_indicator_key(&ip.to_string(), ThreatType::IpBlock);

        {
            let mut indicators = self.indicators.write();
            indicators.insert(
                key.clone(),
                ThreatIndicatorEntry {
                    indicator: indicator.clone(),
                    received_from: None,
                    local_origin: true,
                    version: *self.local_version.read(),
                },
            );
        }

        *self.local_version.write() += 1;
        self.persist_if_needed();

        if self.config.push_enabled {
            let threshold = self.config.push_severity_threshold as u32;
            if ThreatSeverity::High as u32 >= threshold {
                self.publish_indicator_to_dht(&indicator);
                self.queue_for_push(indicator.clone());

                // Immediate Gossip for high-priority threats
                let gossip_msg = MeshMessage::HotThreatGossip {
                    bloom_filter: Vec::new(),
                    hashes: 0,
                    timestamp: now,
                    immediate_indicator: Some(indicator),
                };
                let sender = self.mesh_sender.read().clone();
                if let Some(tx) = sender {
                    let _ = tx.try_send(gossip_msg);
                }
            }
        } else {
            self.publish_indicator_to_dht(&indicator);
        }
    }

    pub fn add_feed_indicator(&self, indicator: ThreatIndicator) {
        let key = format!(
            "threat_indicator:{}:{:?}",
            indicator.indicator_value, indicator.threat_type
        );

        {
            let mut indicators = self.indicators.write();
            indicators.insert(
                key,
                ThreatIndicatorEntry {
                    indicator: indicator.clone(),
                    received_from: Some("feed".to_string()),
                    local_origin: false,
                    version: *self.local_version.read(),
                },
            );
        }

        *self.local_version.write() += 1;
        self.persist_if_needed();

        if !indicator.site_scope.is_empty() {
            self.publish_feed_indicator_to_dht(&indicator);
        } else {
            self.publish_indicator_to_dht(&indicator);
        }

        let indicator_value = indicator.indicator_value.clone();
        let indicator_type = indicator.threat_type;
        let indicator_scope = indicator.site_scope.clone();
        let indicator_severity = indicator.severity;

        if self.config.push_enabled {
            let threshold = self.config.push_severity_threshold as u32;
            if (indicator_severity as u32) >= threshold {
                self.queue_for_push(indicator);
            }
        }

        tracing::debug!(
            "Added feed indicator: {} ({}) scope={}",
            indicator_value,
            indicator_type as u8,
            indicator_scope
        );
    }

    pub fn announce_honeypot_indicator(
        &self,
        ip: IpAddr,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        reason: String,
        ttl_seconds: Option<u64>,
        site_scope: &str,
    ) {
        let now = crate::mesh::safe_unix_timestamp();

        let mut signature = Vec::new();
        let mut signer_public_key = None;

        if let Some(ref signer) = self.signer {
            let content = format!(
                "{}:{}:{}:{}:{}",
                ip, threat_type as u8, severity as u8, now, self.node_id
            );
            signature = signer.sign(content.as_bytes());
            signer_public_key = Some(signer.get_public_key());
        }

        let indicator = ThreatIndicator {
            threat_type,
            indicator_value: ip.to_string(),
            severity,
            reason: reason.clone(),
            ttl_seconds: ttl_seconds.unwrap_or(self.config.min_ttl_seconds * 6),
            source_node_id: self.node_id.clone(),
            timestamp: now,
            site_scope: site_scope.to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature,
            signer_public_key,
        };

        let key = make_indicator_key(&ip.to_string(), threat_type);

        {
            let mut indicators = self.indicators.write();
            indicators.insert(
                key,
                ThreatIndicatorEntry {
                    indicator: indicator.clone(),
                    received_from: None,
                    local_origin: true,
                    version: *self.local_version.read(),
                },
            );
        }

        *self.local_version.write() += 1;
        self.persist_if_needed();

        let threshold = self.config.push_severity_threshold as u32;
        if self.config.push_enabled && (severity as u32) >= threshold {
            self.publish_indicator_to_dht(&indicator);
            self.queue_for_push(indicator);
        } else {
            self.publish_indicator_to_dht(&indicator);
        }

        if severity == ThreatSeverity::High || severity == ThreatSeverity::Critical {
            let ttl = ttl_seconds.unwrap_or(self.config.min_ttl_seconds * 6);
            self.block_store.block_ip(ip, &reason, ttl, site_scope);
            tracing::info!(
                "Honeypot detected high/critical threat from {}, blocking locally for {} seconds",
                ip,
                ttl
            );
        }

        tracing::debug!("Announced honeypot indicator: {} from {}", reason, ip);
    }

    pub fn announce_local_rate_limit(
        &self,
        ip: IpAddr,
        requests: u64,
        window_secs: u64,
        site_scope: String,
    ) {
        let now = crate::mesh::safe_unix_timestamp();

        let ttl = window_secs.max(self.config.min_ttl_seconds);

        let indicator = ThreatIndicator {
            threat_type: ThreatType::RateLimitViolation,
            indicator_value: ip.to_string(),
            severity: ThreatSeverity::Medium,
            reason: format!("Rate limit exceeded: {} reqs in {}s", requests, window_secs),
            ttl_seconds: ttl,
            source_node_id: self.node_id.clone(),
            timestamp: now,
            site_scope: site_scope.clone(),
            rate_limit_requests: Some(requests),
            rate_limit_window_secs: Some(window_secs),
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };

        let key = make_indicator_key(&ip.to_string(), ThreatType::RateLimitViolation);

        {
            let mut indicators = self.indicators.write();
            indicators.insert(
                key.clone(),
                ThreatIndicatorEntry {
                    indicator: indicator.clone(),
                    received_from: None,
                    local_origin: true,
                    version: *self.local_version.read(),
                },
            );
        }

        *self.local_version.write() += 1;
        self.persist_if_needed();

        self.publish_indicator_to_dht(&indicator);
        if self.config.push_enabled {
            let threshold = self.config.push_severity_threshold as u32;
            if ThreatSeverity::Medium as u32 >= threshold {
                self.queue_for_push(indicator);
            }
        }

        tracing::debug!(
            "Announced local rate limit: {} ({} reqs/{}s)",
            ip,
            requests,
            window_secs
        );
    }

    pub fn announce_local_suspicious(
        &self,
        ip: IpAddr,
        pattern: String,
        severity: ThreatSeverity,
        site_scope: String,
    ) {
        let now = crate::mesh::safe_unix_timestamp();

        let ttl = match severity {
            ThreatSeverity::Critical => 7200,
            ThreatSeverity::High => 3600,
            ThreatSeverity::Medium => 1800,
            ThreatSeverity::Low => 900,
            ThreatSeverity::Unspecified => 300,
        };

        let indicator = ThreatIndicator {
            threat_type: ThreatType::SuspiciousActivity,
            indicator_value: ip.to_string(),
            severity,
            reason: format!("Suspicious activity: {}", pattern),
            ttl_seconds: ttl.max(self.config.min_ttl_seconds),
            source_node_id: self.node_id.clone(),
            timestamp: now,
            site_scope: site_scope.clone(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: Some(pattern),
            signature: Vec::new(),
            signer_public_key: None,
        };

        let key = make_indicator_key(&ip.to_string(), ThreatType::SuspiciousActivity);

        {
            let mut indicators = self.indicators.write();
            indicators.insert(
                key.clone(),
                ThreatIndicatorEntry {
                    indicator: indicator.clone(),
                    received_from: None,
                    local_origin: true,
                    version: *self.local_version.read(),
                },
            );
        }

        *self.local_version.write() += 1;
        self.persist_if_needed();

        let indicator_reason = indicator.reason.clone();

        self.publish_indicator_to_dht(&indicator);
        if self.config.push_enabled {
            let threshold = self.config.push_severity_threshold as u32;
            if severity as u32 >= threshold {
                self.queue_for_push(indicator);
            }
        }

        tracing::info!(
            "Announced local suspicious activity: {} ({})",
            ip,
            indicator_reason
        );
    }

    fn queue_for_push(&self, indicator: ThreatIndicator) {
        if self.config.hub_only_mode && !self.node_role.is_global() {
            tracing::debug!("Skipping push for non-global node in hub_only_mode");
            return;
        }

        let mut queue = self.pending_announces.write();

        if queue.len() >= MAX_PENDING_INDICATORS {
            queue.pop_front();
        }

        queue.push_back(indicator);
    }

    pub fn publish_indicator_to_dht(&self, indicator: &ThreatIndicator) {
        if !self.config.enabled {
            return;
        }

        if self.config.hub_only_mode && !self.node_role.is_global() {
            static WARNED_ONCE: std::sync::LazyLock<std::sync::Mutex<bool>> =
                std::sync::LazyLock::new(|| std::sync::Mutex::new(false));
            let mut warned = WARNED_ONCE.lock().unwrap();
            if !*warned {
                tracing::warn!(
                    "DHT publish skipped for non-global node in hub_only_mode (standalone). \
                     Threat intel will not be distributed to mesh."
                );
                *warned = true;
            }
            return;
        }

        if self.signer.is_none() {
            tracing::warn!("Cannot publish threat indicator: no signer configured");
            return;
        }

        let transport_opt = self.transport.read().clone();
        let Some(transport) = transport_opt else {
            tracing::debug!("Transport not available for DHT publish");
            return;
        };

        let Some(record_store) = transport.get_record_store() else {
            tracing::debug!("Record store not available for DHT publish");
            return;
        };

        let key = DhtKey::threat_indicator(
            &indicator.indicator_value,
            &format!("{:?}", indicator.threat_type),
        );
        let key_str = key.as_str();

        let (signature, signer_public_key) = if let Some(ref signer) = self.signer {
            let content = format!(
                "{}:{}:{}:{}:{}",
                indicator.indicator_value,
                indicator.threat_type as u8,
                indicator.severity as u8,
                indicator.timestamp,
                indicator.source_node_id
            );
            let sig = signer.sign(content.as_bytes());
            let pk = signer.get_public_key();
            (sig, Some(pk))
        } else {
            (Vec::new(), None)
        };

        let value = serde_json::json!({
            "indicator_value": indicator.indicator_value,
            "threat_type": indicator.threat_type as u8,
            "severity": indicator.severity as u8,
            "reason": indicator.reason,
            "ttl_seconds": indicator.ttl_seconds,
            "source_node_id": indicator.source_node_id,
            "timestamp": indicator.timestamp,
            "site_scope": indicator.site_scope,
            "rate_limit_requests": indicator.rate_limit_requests,
            "rate_limit_window_secs": indicator.rate_limit_window_secs,
            "suspicious_pattern": indicator.suspicious_pattern,
            "signature": signature,
            "signer_public_key": signer_public_key,
        });

        if let Ok(bytes) = serde_json::to_vec(&value) {
            let ttl = indicator.ttl_seconds.max(self.config.min_ttl_seconds);
            let is_critical_threat = indicator.severity == ThreatSeverity::Critical
                || indicator.severity == ThreatSeverity::High;

            let stored = if is_critical_threat && self.node_role.is_global() {
                record_store.store_and_announce_critical(
                    key_str.to_string(),
                    bytes,
                    ttl,
                    record_store.replication_factor(),
                )
            } else {
                record_store.store_and_announce(key_str.to_string(), bytes, ttl)
            };

            if stored {
                metrics::record_threat_intel_dht_publish();
                tracing::debug!(
                    "Published threat indicator to DHT: {} ({})",
                    indicator.indicator_value,
                    indicator.threat_type as u8
                );
            } else {
                metrics::record_threat_intel_dht_publish_failed();
            }
        } else {
            metrics::record_threat_intel_dht_publish_failed();
        }
    }

    pub fn publish_feed_indicator_to_dht(&self, indicator: &ThreatIndicator) {
        if !self.config.enabled {
            return;
        }

        if self.signer.is_none() {
            tracing::warn!("Cannot publish feed indicator: no signer configured");
            return;
        }

        let transport_opt = self.transport.read().clone();
        let Some(transport) = transport_opt else {
            tracing::debug!("Transport not available for feed DHT publish");
            return;
        };

        let Some(record_store) = transport.get_record_store() else {
            tracing::debug!("Record store not available for feed DHT publish");
            return;
        };

        let site_scope = if indicator.site_scope.is_empty() {
            "global".to_string()
        } else {
            indicator.site_scope.clone()
        };

        let inner_key = DhtKey::threat_indicator(
            &indicator.indicator_value,
            &format!("{:?}", indicator.threat_type),
        );
        let scoped_key = DhtKey::site_scoped(&site_scope, inner_key);
        let key_str = scoped_key.as_str();

        let (signature, signer_public_key) = if let Some(ref signer) = self.signer {
            let content = format!(
                "{}:{}:{}:{}:{}",
                indicator.indicator_value,
                indicator.threat_type as u8,
                indicator.severity as u8,
                indicator.timestamp,
                indicator.source_node_id
            );
            let sig = signer.sign(content.as_bytes());
            let pk = signer.get_public_key();
            (sig, Some(pk))
        } else {
            (Vec::new(), None)
        };

        let value = match crate::serialization::serialize(indicator) {
            Ok(bytes) => bytes,
            Err(_) => {
                metrics::record_threat_intel_dht_publish_failed();
                return;
            }
        };

        let ttl = indicator.ttl_seconds.max(self.config.min_ttl_seconds);

        if record_store.store_and_announce(key_str.to_string(), value, ttl) {
            metrics::record_threat_intel_dht_publish();
            tracing::debug!(
                "Published feed indicator to DHT (SiteScoped): {} ({}) scope={}",
                indicator.indicator_value,
                indicator.threat_type as u8,
                site_scope
            );
        } else {
            metrics::record_threat_intel_dht_publish_failed();
        }
    }

    pub fn handle_incoming_threat(
        &self,
        indicator: ThreatIndicator,
        from_node: &str,
        from_role: MeshNodeRole,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> bool {
        if let Some(signer) = signer {
            if !indicator.signature.is_empty() {
                if let Some(ref pk) = indicator.signer_public_key {
                    let content = format!(
                        "{}:{}:{}:{}:{}",
                        indicator.indicator_value,
                        indicator.threat_type as u8,
                        indicator.severity as u8,
                        indicator.timestamp,
                        indicator.source_node_id
                    );
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    if !signer.verify(content.as_bytes(), &indicator.signature, &pk_bytes) {
                        tracing::warn!(
                            "Signature verification failed for threat from {}",
                            from_node
                        );
                        return false;
                    }
                    tracing::debug!("Signature verified for threat from {}", from_node);
                }
            }
        }

        let decision = self.reputation.evaluate_threat(from_node, from_role);

        if !decision.accepted {
            tracing::warn!(
                "Rejected threat from {} (role: {:?}, score: {}): {}",
                from_node,
                from_role,
                decision.reputation_score,
                decision.reason
            );
            self.reputation.record_threat_rejected(from_node);
            return false;
        }

        let key = make_indicator_key(&indicator.indicator_value, indicator.threat_type);

        let now = crate::mesh::safe_unix_timestamp();

        let expires_at = indicator.timestamp + indicator.ttl_seconds;
        if now > expires_at {
            tracing::warn!("Received expired threat indicator: {}", key);
            return false;
        }

        if let Some(existing) = self.indicators.read().get(&key) {
            if existing.indicator.indicator_value == indicator.indicator_value
                && existing.indicator.threat_type == indicator.threat_type
            {
                tracing::debug!("Duplicate threat indicator received, skipping: {}", key);
                return true;
            }
        }

        match indicator.threat_type {
            ThreatType::IpBlock => {
                if let Ok(ip) = indicator.indicator_value.parse::<IpAddr>() {
                    if self.is_global_node_ip(ip) {
                        tracing::warn!(
                            "Ignored block attempt for global node IP {} from {}",
                            ip,
                            from_node
                        );
                        return false;
                    }

                    let banned = self.block_store.block_ip(
                        ip,
                        &format!("mesh:{}:{}", from_node, indicator.reason),
                        indicator.ttl_seconds,
                        &indicator.site_scope,
                    );

                    if banned {
                        tracing::info!(
                            "Applied mesh block from {}: {} (reason: {}, TTL: {}s)",
                            from_node,
                            ip,
                            indicator.reason,
                            indicator.ttl_seconds
                        );
                    }
                }
            }
            ThreatType::RateLimitViolation => {
                if let Ok(ip) = indicator.indicator_value.parse::<IpAddr>() {
                    if self.is_global_node_ip(ip) {
                        tracing::warn!(
                            "Ignored rate limit for global node IP {} from {}",
                            ip,
                            from_node
                        );
                        return false;
                    }
                    self.apply_rate_limit_mesh_action(&indicator, from_node);
                }
            }
            ThreatType::SuspiciousActivity => {
                if let Ok(ip) = indicator.indicator_value.parse::<IpAddr>() {
                    if self.is_global_node_ip(ip) {
                        tracing::warn!(
                            "Ignored suspicious activity for global node IP {} from {}",
                            ip,
                            from_node
                        );
                        return false;
                    }
                    self.apply_suspicious_mesh_action(&indicator, from_node);
                }
            }
            ThreatType::AsnBlock => {
                if let Ok(asn) = indicator.indicator_value.parse::<u32>() {
                    tracing::info!(
                        "Applied mesh ASN block from {}: AS{} (reason: {}, TTL: {}s)",
                        from_node,
                        asn,
                        indicator.reason,
                        indicator.ttl_seconds
                    );
                    crate::metrics::record_attack_type("AsnScraping");
                }
            }
            ThreatType::IpThrottle => {
                if let Ok(ip) = indicator.indicator_value.parse::<IpAddr>() {
                    if self.is_global_node_ip(ip) {
                        tracing::warn!(
                            "Ignored IP throttle for global node IP {} from {}",
                            ip,
                            from_node
                        );
                        return false;
                    }
                    let reqs = indicator.rate_limit_requests.unwrap_or(50);
                    let window = indicator.rate_limit_window_secs.unwrap_or(60);
                    self.block_store.block_ip(
                        ip,
                        &format!("mesh:{}:ip_throttle:{}r/{}s", from_node, reqs, window),
                        indicator.ttl_seconds,
                        &indicator.site_scope,
                    );
                    tracing::info!(
                        "Applied mesh IP throttle from {}: {} ({} reqs/{}s, TTL: {}s)",
                        from_node,
                        ip,
                        reqs,
                        window,
                        indicator.ttl_seconds
                    );
                }
            }
            ThreatType::DomainBlock => {
                if self.is_global_node_ip_string(&indicator.indicator_value) {
                    tracing::warn!(
                        "Ignored domain block for global node domain {} from {}",
                        indicator.indicator_value,
                        from_node
                    );
                    return false;
                }
                tracing::info!(
                    "Received domain block from {}: {} (reason: {}, TTL: {}s) - requires DNS-layer integration",
                    from_node,
                    indicator.indicator_value,
                    indicator.reason,
                    indicator.ttl_seconds
                );
            }
            ThreatType::UrlBlock => {
                if self.is_global_node_ip_string(&indicator.indicator_value) {
                    tracing::warn!(
                        "Ignored URL block for global node URL {} from {}",
                        indicator.indicator_value,
                        from_node
                    );
                    return false;
                }
                tracing::info!(
                    "Received URL block from {}: {} (reason: {}, TTL: {}s) - requires URL-filter integration",
                    from_node,
                    indicator.indicator_value,
                    indicator.reason,
                    indicator.ttl_seconds
                );
            }
            ThreatType::CertBlock => {
                if self.is_global_node_ip_string(&indicator.indicator_value) {
                    tracing::warn!(
                        "Ignored cert block for global node cert {} from {}",
                        indicator.indicator_value,
                        from_node
                    );
                    return false;
                }
                tracing::info!(
                    "Received certificate block from {}: {} (reason: {}, TTL: {}s) - requires TLS-layer integration",
                    from_node,
                    indicator.indicator_value,
                    indicator.reason,
                    indicator.ttl_seconds
                );
            }
            ThreatType::Unspecified => {
                tracing::warn!("Received threat with unspecified type from {}", from_node);
            }
        }

        {
            let mut indicators = self.indicators.write();
            indicators.insert(
                key,
                ThreatIndicatorEntry {
                    indicator: indicator.clone(),
                    received_from: Some(from_node.to_string()),
                    local_origin: false,
                    version: *self.local_version.read(),
                },
            );
        }

        *self.local_version.write() += 1;
        self.persist_if_needed();
        self.reputation.record_threat_accepted(from_node);

        tracing::debug!(
            "Accepted threat from {} (score: {})",
            from_node,
            decision.reputation_score
        );
        true
    }

    pub fn lookup_threat_indicator_in_dht(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> Option<ThreatIndicator> {
        let transport = self.transport.read().clone()?;
        let record_store = transport.get_record_store()?;

        let key = DhtKey::threat_indicator(indicator_value, &format!("{:?}", threat_type));
        let key_str = key.as_str();

        let record = match record_store.get(&key_str) {
            Some(r) => r,
            None => {
                metrics::record_threat_intel_dht_lookup_miss();
                return None;
            }
        };

        let indicator: ThreatIndicator = match serde_json::from_slice(&record.value) {
            Ok(v) => v,
            Err(_) => match crate::serialization::deserialize(&record.value) {
                Ok(v) => v,
                Err(_) => {
                    metrics::record_threat_intel_dht_lookup_miss();
                    return None;
                }
            },
        };

        metrics::record_threat_intel_dht_lookup_hit();
        Some(indicator)
    }

    pub fn lookup_local_indicator(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> Option<ThreatIndicator> {
        let key = make_indicator_key(indicator_value, threat_type);
        let indicators = self.indicators.read();
        indicators.get(&key).map(|entry| entry.indicator.clone())
    }

    pub fn lookup_local_indicator_by_ip(&self, ip: &str) -> Option<ThreatIndicator> {
        self.lookup_local_indicator(ip, ThreatType::IpBlock)
    }

    pub fn is_mesh_available(&self) -> bool {
        self.transport.read().is_some()
    }

    pub fn get_node_role(&self) -> MeshNodeRole {
        self.node_role
    }

    fn apply_rate_limit_mesh_action(&self, indicator: &ThreatIndicator, from_node: &str) {
        if let Ok(ip) = indicator.indicator_value.parse::<IpAddr>() {
            let reqs = indicator.rate_limit_requests.unwrap_or(100);
            let window = indicator.rate_limit_window_secs.unwrap_or(60);

            self.block_store.block_ip(
                ip,
                &format!("mesh:{}:ratelimit:{}r/{}s", from_node, reqs, window),
                indicator.ttl_seconds,
                &indicator.site_scope,
            );

            tracing::info!(
                "Applied mesh rate limit from {}: {} ({} reqs/{}s)",
                from_node,
                ip,
                reqs,
                window
            );
        }
    }

    fn apply_suspicious_mesh_action(&self, indicator: &ThreatIndicator, from_node: &str) {
        if let Ok(ip) = indicator.indicator_value.parse::<IpAddr>() {
            let severity_ttl = match indicator.severity {
                ThreatSeverity::Critical => 7200,
                ThreatSeverity::High => 3600,
                ThreatSeverity::Medium => 1800,
                ThreatSeverity::Low => 900,
                ThreatSeverity::Unspecified => 300,
            };

            self.block_store.block_ip(
                ip,
                &format!("mesh:{}:suspicious", from_node),
                severity_ttl,
                &indicator.site_scope,
            );

            tracing::info!(
                "Applied mesh suspicious activity block from {}: {} (severity: {:?})",
                from_node,
                ip,
                indicator.severity
            );
        }
    }

    pub fn should_sync(&self) -> bool {
        if !self.config.sync_enabled {
            return false;
        }

        let last = *self.last_sync.read();
        last.elapsed() > Duration::from_secs(self.config.sync_interval_secs)
    }

    pub fn record_sync(&self) {
        *self.last_sync.write() = Instant::now();
    }

    pub fn get_indicators_for_sync(&self, from_version: u64) -> Vec<ThreatIndicator> {
        let indicators = self.indicators.read();

        indicators
            .values()
            .filter(|entry| entry.version > from_version)
            .map(|entry| entry.indicator.clone())
            .take(self.config.max_indicators_per_message)
            .collect()
    }

    pub fn apply_sync(
        &self,
        indicators: Vec<ThreatIndicator>,
        from_node: &str,
        from_role: MeshNodeRole,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> Vec<String> {
        let mut removed_keys = Vec::new();

        for indicator in indicators {
            let key = make_indicator_key(&indicator.indicator_value, indicator.threat_type);

            let accepted = self.handle_incoming_threat(indicator, from_node, from_role, signer);

            if !accepted {
                removed_keys.push(key);
            }
        }

        removed_keys
    }

    pub fn get_version(&self) -> u64 {
        *self.local_version.read()
    }

    pub fn get_indicator_count(&self) -> usize {
        self.indicators.read().len()
    }

    pub fn cleanup_expired(&self) {
        let now = crate::mesh::safe_unix_timestamp();

        let mut indicators = self.indicators.write();
        indicators.retain(|_, entry| {
            let expires_at = entry.indicator.timestamp + entry.indicator.ttl_seconds;
            now < expires_at
        });

        if indicators.len() != self.indicators.read().len() {
            tracing::debug!("Cleaned up expired threat indicators");
        }
    }

    pub fn sync_from_dht(&self) -> Result<(), String> {
        metrics::record_threat_intel_dht_sync();

        let transport = self.transport.read().clone();
        let record_store = match transport {
            Some(t) => t,
            None => {
                metrics::record_threat_intel_dht_sync_failed();
                return Err("Transport not set".to_string());
            }
        };

        let record_store = match record_store.get_record_store() {
            Some(rs) => rs,
            None => {
                metrics::record_threat_intel_dht_sync_failed();
                return Err("Record store not available".to_string());
            }
        };

        let dht_records =
            record_store.get_by_prefix("threat_indicator:", DEFAULT_GET_BY_PREFIX_LIMIT);
        let mut local_indicators = self.indicators.write();

        let dht_keys: std::collections::HashSet<String> =
            dht_records.iter().map(|r| r.key.clone()).collect();

        let mut added = 0;
        let mut removed = 0;

        for key in &dht_keys {
            let record = match record_store.get(key) {
                Some(r) => r,
                None => continue,
            };

            let should_update = if let Some(existing) = local_indicators.get(key) {
                if existing.local_origin {
                    continue;
                }
                record.timestamp > existing.version
            } else {
                true
            };

            if should_update {
                let indicator = match self.parse_dht_record_value(&record.value) {
                    Some(i) => i,
                    None => continue,
                };

                let signature = &indicator.signature;
                let signer_pk = indicator.signer_public_key.as_deref().unwrap_or("");

                if !signature.is_empty() && !signer_pk.is_empty() {
                    let content = format!(
                        "{}:{}:{}:{}:{}",
                        indicator.indicator_value,
                        indicator.threat_type as u8,
                        indicator.severity as u8,
                        indicator.timestamp,
                        indicator.source_node_id
                    );
                    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                    let sig_bytes = signature.clone();
                    let pk_bytes = match URL_SAFE_NO_PAD.decode(signer_pk) {
                        Ok(p) => p,
                        Err(_) => {
                            tracing::warn!(
                                "Threat intel DHT sync: invalid signer pk base64 for {}",
                                key
                            );
                            continue;
                        }
                    };

                    let pk_bytes: [u8; 32] = match pk_bytes.clone().try_into() {
                        Ok(p) => p,
                        Err(_) => {
                            tracing::warn!(
                                "Threat intel DHT sync: invalid signer pk length for {} (expected 32 bytes, got {})",
                                key,
                                pk_bytes.len()
                            );
                            continue;
                        }
                    };

                    let signer = crate::mesh::protocol::MeshMessageSigner::new(pk_bytes);
                    if !signer.verify(content.as_bytes(), &sig_bytes, &pk_bytes) {
                        tracing::warn!(
                            "Threat intel DHT sync: signature verification failed for {}",
                            key
                        );
                        continue;
                    }

                    if !self.is_global_node() {
                        let trusted =
                            self.check_trusted_signer(&indicator.source_node_id, Some(signer_pk));
                        if !trusted {
                            tracing::warn!(
                                "Threat intel DHT sync: indicator from untrusted node {} rejected",
                                indicator.source_node_id
                            );
                            continue;
                        }
                    }
                } else {
                    tracing::warn!(
                        "Threat intel DHT sync: missing signature or signer pk for {}",
                        key
                    );
                    continue;
                }

                local_indicators.insert(
                    key.to_string(),
                    ThreatIndicatorEntry {
                        indicator,
                        received_from: Some("dht_sync".to_string()),
                        local_origin: false,
                        version: record.timestamp,
                    },
                );
                added += 1;
            }
        }

        local_indicators.retain(|key, entry| {
            if entry.local_origin {
                return true;
            }
            if !dht_keys.contains(key) {
                removed += 1;
                return false;
            }
            true
        });

        *self.local_version.write() += 1;

        metrics::record_threat_intel_dht_sync_added(added as u64);
        metrics::record_threat_intel_dht_sync_removed(removed as u64);
        metrics::record_threat_intel_dht_sync_success();

        tracing::info!(
            "Synced threat indicators from DHT: {} added, {} removed, {} total",
            added,
            removed,
            local_indicators.len()
        );

        Ok(())
    }

    fn check_trusted_signer(&self, source_node_id: &str, signer_pk: Option<&str>) -> bool {
        if self.node_role.is_global() {
            return true;
        }

        let Some(signer_pk) = signer_pk else {
            return false;
        };

        if signer_pk.is_empty() {
            return false;
        }

        if self.config.trusted_signers.is_empty() {
            let transport = self.transport.read();
            if let Some(ref t) = *transport {
                let topology = t.get_topology();
                return tokio::runtime::Handle::current()
                    .block_on(topology.get_global_nodes())
                    .contains(&source_node_id.to_string());
            }
            return false;
        }

        self.config.trusted_signers.contains(&signer_pk.to_string())
    }

    fn is_global_node(&self) -> bool {
        self.node_role.is_global()
    }

    fn parse_dht_record_value(&self, record_value: &[u8]) -> Option<ThreatIndicator> {
        if let Ok(indicator) = serde_json::from_slice(record_value) {
            return Some(indicator);
        }
        if let Ok(indicator) = crate::serialization::deserialize(record_value) {
            return Some(indicator);
        }
        None
    }

    pub fn create_threat_announce(&self) -> Option<MeshMessage> {
        let mut queue = self.pending_announces.write();
        let indicators: Vec<ThreatIndicator> = queue.drain(..).collect();
        if indicators.is_empty() {
            return None;
        }
        drop(queue);
        let highest_severity = indicators
            .iter()
            .map(|i| i.severity)
            .max_by_key(|s| *s as u32)
            .unwrap_or(ThreatSeverity::Unspecified);

        let mut signature = Vec::new();
        let source_reputation = self
            .reputation
            .get_peer_reputation(&self.node_id)
            .map(|p| p.score)
            .unwrap_or(50);

        let mut signer_public_key = None;

        if let Some(ref signer) = self.signer {
            let request_id = uuid::Uuid::new_v4().to_string();
            let timestamp = MeshMessage::generate_timestamp();

            // Compute a Merkle root of all indicators for payload integrity (Phase 3.1)
            let mut records = HashMap::new();
            for indicator in &indicators {
                let key = format!(
                    "{}:{}",
                    indicator.indicator_value, indicator.threat_type as u8
                );
                let value = format!("{}:{}", indicator.reason, indicator.timestamp).into_bytes();
                records.insert(key, value);
            }
            let tree = crate::mesh::dht::merkle::MerkleTree::from_records(&records);
            let merkle_root = tree.root_hash().unwrap_or_else(|| vec![0u8; 32]);

            let content = format!(
                "{},{},{:?},{},{},{}",
                request_id,
                self.node_id,
                highest_severity,
                self.node_role.bits(),
                timestamp,
                hex::encode(merkle_root)
            );
            signature = signer.sign_smart(content.as_bytes(), true);
            signer_public_key = Some(signer.get_public_key());
        }

        let request_id = uuid::Uuid::new_v4().to_string();

        let message = MeshMessage::ThreatAnnounce {
            request_id: request_id.into(),
            indicators,
            highest_severity,
            timestamp: MeshMessage::generate_timestamp(),
            source_node_id: self.node_id.clone().into(),
            source_role: self.node_role,
            source_reputation: source_reputation as u64,
            signature,
            signer_public_key,
        };

        Some(message)
    }

    pub fn create_sync_request(&self) -> MeshMessage {
        MeshMessage::ThreatSyncRequest {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            node_id: self.node_id.clone().into(),
            from_version: *self.local_version.read(),
            prefer_delta: true,
        }
    }

    pub fn create_sync_response(&self, request_id: &str, from_version: u64) -> MeshMessage {
        let indicators = self.get_indicators_for_sync(from_version);

        let mut signature = Vec::new();
        let mut signer_public_key = None;
        if let Some(ref signer) = self.signer {
            let timestamp = MeshMessage::generate_timestamp();
            let content = format!(
                "{},{},{},{}",
                request_id,
                *self.local_version.read(),
                indicators.len(),
                timestamp
            );
            signature = signer.sign(content.as_bytes());
            signer_public_key = Some(signer.get_public_key());
        }

        MeshMessage::ThreatSyncResponse {
            request_id: request_id.into(),
            indicators,
            version: *self.local_version.read(),
            is_delta: true,
            removed_indicators: Vec::new(),
            signature,
            signer_public_key,
        }
    }

    pub fn get_stats(&self) -> ThreatIntelligenceStats {
        ThreatIntelligenceStats {
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            version: *self.local_version.read(),
            indicator_count: self.indicators.read().len(),
            pending_push_count: self.pending_announces.read().len(),
            last_sync: *self.last_sync.read(),
            reputation_stats: self.reputation.get_all_stats(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreatIntelligenceStats {
    pub node_id: String,
    pub node_role: MeshNodeRole,
    pub version: u64,
    pub indicator_count: usize,
    pub pending_push_count: usize,
    pub last_sync: Instant,
    pub reputation_stats: Vec<crate::mesh::reputation::PeerReputationStats>,
}

impl ThreatIntelligenceManager {
    // Mesh sender lock held briefly across channel send await; low contention.
    #[allow(clippy::await_holding_lock)]
    pub async fn broadcast_pending_threats(&self) {
        if !self.config.enabled || !self.config.push_enabled {
            return;
        }

        let pending_count = self.pending_announces.read().len();
        if pending_count == 0 {
            return;
        }

        if pending_count < 3 {
            tracing::debug!(
                "Skipping threat broadcast: only {} pending (threshold 3)",
                pending_count
            );
            return;
        }

        let highest_severity = {
            let queue = self.pending_announces.read();
            queue
                .iter()
                .map(|i| i.severity)
                .max_by_key(|s| *s as u32)
                .unwrap_or(ThreatSeverity::Unspecified)
        };

        let should_broadcast_all = highest_severity == ThreatSeverity::Critical
            || highest_severity == ThreatSeverity::High;

        let Some(message) = self.create_threat_announce() else {
            return;
        };

        let transport_opt = self.transport.read().clone();
        if let Some(transport) = transport_opt {
            if should_broadcast_all {
                let (success, fail, _) = transport.broadcast_to_all_peers(message, None).await;
                tracing::debug!(
                    "Broadcast all threat announce (severity {:?}): {} sent, {} failed",
                    highest_severity,
                    success,
                    fail
                );
            } else {
                let fanout_factor = self.config.fanout_factor;
                let (success, fail) = transport
                    .broadcast_to_random_peers(message, fanout_factor, None)
                    .await;
                tracing::debug!("Fanout threat announce: {} sent, {} failed", success, fail);
            }
        } else {
            let sender = self.mesh_sender.read().clone();
            if let Some(sender) = sender {
                if let Err(e) = sender.send(message).await {
                    tracing::warn!("Failed to broadcast threat announce: {}", e);
                } else {
                    tracing::debug!("Broadcast threat announce to mesh");
                }
            } else {
                tracing::debug!("No transport or mesh_sender available for broadcast");
            }
        }
    }

    pub fn handle_mesh_message(
        &self,
        message: &MeshMessage,
        from_node: &str,
        from_role: MeshNodeRole,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> Option<MeshMessage> {
        match message {
            MeshMessage::ThreatAnnounce {
                request_id,
                indicators,
                highest_severity: _,
                timestamp,
                source_node_id,
                source_role,
                source_reputation: _,
                signature,
                signer_public_key,
            } => {
                tracing::info!(
                    "Received ThreatAnnounce from {} with {} indicators",
                    from_node,
                    indicators.len()
                );

                if let Some(signer) = signer {
                    if !signature.is_empty() {
                        // Compute a Merkle root of all indicators for payload integrity check (Phase 3.1)
                        let mut records = HashMap::new();
                        for indicator in indicators {
                            let key = format!(
                                "{}:{}",
                                indicator.indicator_value, indicator.threat_type as u8
                            );
                            let value = format!("{}:{}", indicator.reason, indicator.timestamp)
                                .into_bytes();
                            records.insert(key, value);
                        }
                        let tree = crate::mesh::dht::merkle::MerkleTree::from_records(&records);
                        let merkle_root = tree.root_hash().unwrap_or_else(|| vec![0u8; 32]);

                        // The highest_severity was dropped in destructuring, but we need it for verification if it was signed.
                        let highest_sev = indicators
                            .iter()
                            .map(|i| i.severity)
                            .max_by_key(|s| *s as u32)
                            .unwrap_or(ThreatSeverity::Unspecified);

                        let content = format!(
                            "{},{},{:?},{},{},{}",
                            request_id,
                            source_node_id,
                            highest_sev,
                            source_role.bits(),
                            timestamp,
                            hex::encode(merkle_root)
                        );
                        let pk_bytes = if signer_public_key.as_ref().map_or(true, |s| s.is_empty())
                        {
                            Vec::new()
                        } else {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(signer_public_key.as_deref().unwrap_or(""))
                                .unwrap_or_default()
                        };
                        if !signer.verify_any(content.as_bytes(), signature, &pk_bytes) {
                            tracing::warn!(
                                "ThreatAnnounce signature verification failed from {} (Merkle root mismatch or metadata error)",
                                from_node
                            );
                            return Some(MeshMessage::ThreatAcknowledgement {
                                original_request_id: request_id.clone(),
                                node_id: self.node_id.clone().into(),
                                accepted: false,
                                reason: "Invalid signature or Merkle root".into(),
                                timestamp: MeshMessage::generate_timestamp(),
                            });
                        }

                        // C7: Check trusted signers for non-global nodes
                        if !self.node_role.is_global() {
                            if self.config.trusted_signers.is_empty() {
                                tracing::warn!(
                                    "ThreatAnnounce rejected: no trusted_signers configured, rejecting threat from non-global node"
                                );
                                return Some(MeshMessage::ThreatAcknowledgement {
                                    original_request_id: request_id.clone(),
                                    node_id: self.node_id.clone().into(),
                                    accepted: false,
                                    reason: "No trusted_signers configured".into(),
                                    timestamp: MeshMessage::generate_timestamp(),
                                });
                            }
                            if !self
                                .check_trusted_signer(source_node_id, signer_public_key.as_deref())
                            {
                                tracing::warn!(
                                    "ThreatAnnounce rejected: signer {:?} not in trusted_signers list",
                                    signer_public_key
                                );
                                return Some(MeshMessage::ThreatAcknowledgement {
                                    original_request_id: request_id.clone(),
                                    node_id: self.node_id.clone().into(),
                                    accepted: false,
                                    reason: "Signer not in trusted_signers list".into(),
                                    timestamp: MeshMessage::generate_timestamp(),
                                });
                            }
                        }
                    }
                }

                // Phase 3.1: Gossip Relaying
                let request_id_str = request_id.to_string();
                if self.seen_announces.get(&request_id_str).is_none() {
                    self.seen_announces.insert(request_id_str, true);

                    if let Some(transport) = self.transport.read().as_ref() {
                        let fanout_factor = self.config.fanout_factor;
                        let relay_msg = message.clone();
                        let transport_clone = transport.clone();
                        tokio::spawn(async move {
                            let _ = transport_clone
                                .broadcast_to_random_peers(relay_msg, fanout_factor, None)
                                .await;
                        });
                    }
                }

                let mut accepted_count = 0;
                for indicator in indicators {
                    if self.handle_incoming_threat(indicator.clone(), from_node, from_role, signer)
                    {
                        accepted_count += 1;
                    }
                }

                tracing::info!(
                    "Accepted {}/{} threats from {}",
                    accepted_count,
                    indicators.len(),
                    from_node
                );

                Some(MeshMessage::ThreatAcknowledgement {
                    original_request_id: request_id.clone(),
                    node_id: self.node_id.clone().into(),
                    accepted: true,
                    reason: format!(
                        "Accepted {}/{} indicators",
                        accepted_count,
                        indicators.len()
                    )
                    .into(),
                    timestamp: MeshMessage::generate_timestamp(),
                })
            }
            MeshMessage::ThreatSyncRequest {
                request_id,
                node_id: _,
                from_version,
                prefer_delta: _,
            } => {
                tracing::debug!(
                    "Received ThreatSyncRequest from {} (version: {})",
                    from_node,
                    from_version
                );
                Some(self.create_sync_response(request_id, *from_version))
            }
            MeshMessage::ThreatAcknowledgement {
                original_request_id,
                node_id: _,
                accepted,
                reason,
                timestamp: _,
            } => {
                tracing::debug!(
                    "Received ThreatAcknowledgement from {}: accepted={}, reason={}",
                    from_node,
                    accepted,
                    reason
                );
                None
            }
            MeshMessage::ThreatSyncResponse { indicators, .. } => {
                for indicator in indicators {
                    self.handle_incoming_threat(indicator.clone(), from_node, from_role, signer);
                }
                None
            }
            _ => None,
        }
    }

    pub fn start_background_tasks(&self) {
        let config = self.config.clone();
        let node_id = self.node_id.clone();
        let node_role = self.node_role;
        let initial_interval = config.threat_sync_interval_secs;
        let sync_enabled = config.sync_enabled;
        let fanout_factor = config.fanout_factor;
        let re_announce_interval_secs = config.re_announce_interval_secs;

        let threat_intel = Arc::new(self.clone());

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            let mut last_sync = Instant::now();

            loop {
                interval.tick().await;

                threat_intel.reputation.apply_periodic_decay();

                if !config.enabled || !config.push_enabled {
                    continue;
                }

                threat_intel.broadcast_pending_threats().await;

                if sync_enabled && last_sync.elapsed().as_secs() > initial_interval {
                    tracing::debug!("Threat sync interval reached, syncing from DHT");

                    if threat_intel.config.hub_only_mode && !threat_intel.node_role.is_global() {
                        tracing::debug!("Skipping DHT sync in hub_only_mode for non-global node");
                    } else if let Err(e) = threat_intel.sync_from_dht() {
                        tracing::debug!("DHT sync failed: {}", e);
                    } else {
                        threat_intel.record_sync();
                    }

                    last_sync = Instant::now();
                }
            }
        });

        if re_announce_interval_secs > 0 {
            let threat_intel_reattempt = Arc::new(self.clone());
            let re_announce_interval = Duration::from_secs(re_announce_interval_secs);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(re_announce_interval);
                loop {
                    ticker.tick().await;
                    threat_intel_reattempt.re_announce_local_indicators().await;
                }
            });
            tracing::info!(
                "Threat intel re-announce task started (interval: {}s)",
                re_announce_interval_secs
            );
        }

        tracing::info!(
            "Threat intel background tasks started (role: {:?}, sync_enabled: {})",
            node_role,
            sync_enabled
        );
    }

    pub async fn re_announce_local_indicators(&self) {
        if !self.config.enabled {
            return;
        }

        if !self.node_role.is_global() {
            return;
        }

        if self.config.hub_only_mode {
            return;
        }

        let indicators = self.indicators.read();
        let now = crate::mesh::safe_unix_timestamp();

        for (_key, entry) in indicators.iter() {
            let expires_at = entry.indicator.timestamp + entry.indicator.ttl_seconds;
            if now > expires_at {
                continue;
            }

            self.publish_indicator_to_dht(&entry.indicator);
        }
    }

    pub fn get_feed_signable_content(
        &self,
        indicators: &[ThreatIndicator],
        version: u64,
        timestamp: u64,
    ) -> String {
        let indicator_hashes: Vec<String> = indicators
            .iter()
            .map(|i| {
                format!(
                    "{}:{}:{}",
                    i.threat_type as u8, i.indicator_value, i.severity as u8
                )
            })
            .collect();

        format!(
            "{}:{}:{}:{}",
            version,
            timestamp,
            indicators.len(),
            indicator_hashes.join(",")
        )
    }

    pub fn create_signed_feed(
        &self,
        site_id: Option<&str>,
        _key: &ed25519_dalek::VerifyingKey,
    ) -> ThreatFeedPayload {
        let now = crate::mesh::safe_unix_timestamp();
        let version = MESH_MESSAGE_VERSION as u64;

        let indicators = self.indicators.read();
        let filtered: Vec<ThreatIndicator> = if let Some(site) = site_id {
            indicators
                .values()
                .filter(|entry| {
                    entry.indicator.site_scope.is_empty() || entry.indicator.site_scope == site
                })
                .map(|entry| entry.indicator.clone())
                .collect()
        } else {
            indicators
                .values()
                .map(|entry| entry.indicator.clone())
                .collect()
        };
        drop(indicators);

        let feed_indicators: Vec<ThreatFeedIndicator> = filtered
            .iter()
            .map(|i| ThreatFeedIndicator {
                threat_type: i.threat_type as u8,
                indicator_value: i.indicator_value.clone(),
                severity: i.severity as u8,
                reason: i.reason.clone(),
                ttl_seconds: i.ttl_seconds,
                source_node_id: i.source_node_id.clone(),
                site_scope: if i.site_scope.is_empty() {
                    None
                } else {
                    Some(i.site_scope.clone())
                },
                rate_limit_requests: i.rate_limit_requests,
                rate_limit_window_secs: i.rate_limit_window_secs,
                suspicious_pattern: i.suspicious_pattern.clone(),
            })
            .collect();

        let signable_content = self.get_feed_signable_content(&filtered, version, now);

        let (signature, signer_public_key) = if let Some(ref signer) = self.signer {
            let sig = signer.sign(signable_content.as_bytes());
            let pk = signer.get_public_key();
            (sig, Some(pk))
        } else {
            (Vec::new(), None)
        };

        let signature_b64 = if !signature.is_empty() {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature)
        } else {
            String::new()
        };

        ThreatFeedPayload {
            version,
            timestamp: now,
            indicators: feed_indicators,
            signature: signature_b64,
            signer_public_key,
        }
    }

    fn clone_internal(&self) -> Self {
        Self {
            config: self.config.clone(),
            block_store: self.block_store.clone(),
            reputation: self.reputation.clone(),
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            signer: self.signer.clone(),
            local_version: RwLock::new(*self.local_version.read()),
            indicators: RwLock::new(self.indicators.read().clone()),
            pending_announces: RwLock::new(self.pending_announces.read().clone()),
            mesh_sender: self.mesh_sender.clone(),
            transport: self.transport.clone(),
            last_sync: RwLock::new(*self.last_sync.read()),
            global_node_ips: RwLock::new(self.global_node_ips.read().clone()),
            persistence_path: self.persistence_path.clone(),
            seen_announces: self.seen_announces.clone(),
            hot_threats: RwLock::new(bloomfilter::Bloom::new_for_fp_rate(100_000, 0.01)),
        }
    }
}

impl Clone for ThreatIntelligenceManager {
    fn clone(&self) -> Self {
        self.clone_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_indicator(
        value: &str,
        threat_type: ThreatType,
        severity: ThreatSeverity,
    ) -> ThreatIndicator {
        ThreatIndicator {
            threat_type,
            indicator_value: value.to_string(),
            severity,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: 1713523200,
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        }
    }

    fn create_test_manager() -> ThreatIntelligenceManager {
        let config = ThreatIntelligenceConfigInternal {
            enabled: true,
            push_enabled: true,
            sync_enabled: true,
            sync_interval_secs: 300,
            threat_sync_interval_secs: 60,
            push_severity_threshold: ThreatSeverity::Medium,
            min_ttl_seconds: 60,
            max_indicators_per_message: 50,
            hub_only_mode: false,
            reputation_config: ReputationConfig::default(),
            fanout_factor: 0.5,
            re_announce_interval_secs: 300,
            trusted_signers: Vec::new(),
            behavioral_enabled: true,
            min_samples_for_fingerprint: 10,
            fingerprint_ttl_secs: 3600,
            high_severity_threshold: 70,
        };
        let block_store = Arc::new(BlockStore::new(false, None, Default::default()));
        ThreatIntelligenceManager::new(
            config,
            block_store,
            "test-node".to_string(),
            MeshNodeRole::GLOBAL,
            None,
        )
    }

    #[test]
    fn test_get_feed_signable_content_empty() {
        let manager = create_test_manager();
        let indicators: Vec<ThreatIndicator> = vec![];
        let content = manager.get_feed_signable_content(&indicators, 1, 1713523200);
        assert_eq!(content, "1:1713523200:0:");
    }

    #[test]
    fn test_get_feed_signable_content_single_indicator() {
        let manager = create_test_manager();
        let indicators = vec![create_test_indicator(
            "192.168.1.1",
            ThreatType::IpBlock,
            ThreatSeverity::High,
        )];
        let content = manager.get_feed_signable_content(&indicators, 1, 1713523200);
        assert_eq!(content, "1:1713523200:1:1:192.168.1.1:3");
    }

    #[test]
    fn test_get_feed_signable_content_multiple_indicators() {
        let manager = create_test_manager();
        let indicators = vec![
            create_test_indicator("192.168.1.1", ThreatType::IpBlock, ThreatSeverity::High),
            create_test_indicator(
                "10.0.0.1",
                ThreatType::RateLimitViolation,
                ThreatSeverity::Medium,
            ),
        ];
        let content = manager.get_feed_signable_content(&indicators, 1, 1713523200);
        assert_eq!(content, "1:1713523200:2:1:192.168.1.1:3,3:10.0.0.1:2");
    }

    #[test]
    fn test_signable_content_matches_feed_client() {
        use crate::waf::threat_intel::feed_client::ThreatFeedIndicator;
        use crate::waf::threat_intel::feed_client::ThreatFeedPayload;

        let manager = create_test_manager();
        let indicators = vec![
            create_test_indicator("192.168.1.1", ThreatType::IpBlock, ThreatSeverity::High),
            create_test_indicator(
                "10.0.0.1",
                ThreatType::RateLimitViolation,
                ThreatSeverity::Medium,
            ),
        ];

        let version = 1u64;
        let timestamp = 1713523200u64;
        let our_content = manager.get_feed_signable_content(&indicators, version, timestamp);

        let feed_indicators: Vec<ThreatFeedIndicator> = indicators
            .iter()
            .map(|i| ThreatFeedIndicator {
                threat_type: i.threat_type as u8,
                indicator_value: i.indicator_value.clone(),
                severity: i.severity as u8,
                reason: i.reason.clone(),
                ttl_seconds: i.ttl_seconds,
                source_node_id: i.source_node_id.clone(),
                site_scope: None,
                rate_limit_requests: None,
                rate_limit_window_secs: None,
                suspicious_pattern: None,
            })
            .collect();

        let payload = ThreatFeedPayload {
            version,
            timestamp,
            indicators: feed_indicators,
            signature: String::new(),
            signer_public_key: None,
        };

        let feed_client_content =
            crate::waf::threat_intel::feed_client::ThreatFeedClient::get_signable_content(&payload);

        assert_eq!(
            our_content, feed_client_content,
            "Signable content must match ThreatFeedClient format"
        );
    }
}
