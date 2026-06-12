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

use crate::config::MeshNodeRole;
use crate::dht::keys::DhtKey;
use crate::dht::DEFAULT_GET_BY_PREFIX_LIMIT;
use crate::protocol::{
    MeshMessage, MeshPeerInfo, ThreatIndicator, ThreatSeverity, ThreatType, MESH_MESSAGE_VERSION,
};
use crate::reputation::{ReputationConfig, ReputationManager};
use crate::stubs::block_store::{BlockProvenance, BlockProvenanceKind, BlockStoreApi};
use crate::stubs::metrics;
use crate::stubs::waf_stub::threat_intel::feed_client::{ThreatFeedIndicator, ThreatFeedPayload};

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

/// Optional policy context injected into `ThreatIntelligenceManager` so callers
/// do not need to manually pass both trait objects at every call site.
///
/// Default `None` preserves legacy behavior. When set, configured policy
/// evaluation and policy-composed lookup methods use the injected seams.
#[derive(Clone)]
pub struct ThreatIntelPolicyContext {
    canonical: Arc<dyn crate::canonical::CanonicalTrustReader>,
    advisory: Arc<dyn crate::dht::advisory_source::AdvisoryRecordSource>,
}

impl std::fmt::Debug for ThreatIntelPolicyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreatIntelPolicyContext")
            .field("canonical", &"<dyn CanonicalTrustReader>")
            .field("advisory", &"<dyn AdvisoryRecordSource>")
            .finish()
    }
}

impl ThreatIntelPolicyContext {
    pub fn new(
        canonical: Arc<dyn crate::canonical::CanonicalTrustReader>,
        advisory: Arc<dyn crate::dht::advisory_source::AdvisoryRecordSource>,
    ) -> Self {
        Self {
            canonical,
            advisory,
        }
    }

    pub fn canonical(&self) -> &dyn crate::canonical::CanonicalTrustReader {
        self.canonical.as_ref()
    }

    pub fn advisory(&self) -> &dyn crate::dht::advisory_source::AdvisoryRecordSource {
        self.advisory.as_ref()
    }
}

/// Classifies the intent of a threat-intel consumer.
///
/// The consumer kind determines whether enforcement mutations are permitted.
/// Advisory DHT records alone must never cause enforcement — canonical trust
/// is required for action-bearing consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelConsumerKind {
    /// Observability-only consumer. Emits metrics/logs/admin DTOs.
    /// Must not mutate enforcement state.
    ShadowOnly,
    /// Compatibility/debug consumer. Uses raw lookup APIs.
    /// Must not mutate enforcement state.
    RawCompatibility,
    /// Advisory cache/bookkeeping. May store locally for diagnostics.
    /// Must not mutate WAF/block-store/rate-limit state.
    AdvisoryCache,
    /// Enforcement consumer. May mutate block stores, rate limits, WAF deny
    /// lists, or equivalent controls when policy permits action.
    Enforcement,
}

/// Behavior when the policy decision is `Deferred` or the policy context
/// is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelDeferredMode {
    /// Defer to no-action. Suppression is the safe default.
    FailOpenNoAction,
    /// Explicit fail-closed. Suppression with a logged warning.
    FailClosedNoAction,
    /// Shadow/observability only. Never enforces regardless of decision.
    ShadowOnly,
}

/// Result of classifying whether a consumer may act on a threat-intel
/// indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelConsumerAction {
    /// Policy permits the consumer to take enforcement action.
    PermitAction,
    /// Policy suppresses the action. Consumer must not mutate enforcement state.
    SuppressAction,
    /// Consumer is shadow-only. Always suppresses enforcement.
    ShadowOnly,
    /// Consumer is raw-compatibility. Must not be used for enforcement.
    RawCompatibilityOnly,
}

/// Classify whether a consumer may act on a threat-intel indicator given
/// the current policy decision.
///
/// # Semantics
///
/// - `ShadowOnly` → always `ShadowOnly`.
/// - `RawCompatibility` → always `RawCompatibilityOnly`.
/// - `Enforcement + Some(Actionable)` → `PermitAction`.
/// - `Enforcement + Some(AdvisoryOnly | NotActionable)` → `SuppressAction`.
/// - `Enforcement + Some(Deferred)` → behavior depends on `deferred_mode`:
///   - `FailOpenNoAction` → `SuppressAction` (safe default, no enforcement).
///   - `FailClosedNoAction` → `SuppressAction` (explicit fail-closed, logged).
///   - `ShadowOnly` → `ShadowOnly` (observability-only, never enforces).
/// - `Enforcement + None` → `SuppressAction` (missing context must not
///   silently fall back to raw for enforcement).
/// - `AdvisoryCache` → `SuppressAction` (may store locally but not enforce).
pub fn classify_consumer_action(
    decision: Option<&crate::threat_intel_policy::ThreatIntelPolicyDecision>,
    consumer: ThreatIntelConsumerKind,
    deferred_mode: ThreatIntelDeferredMode,
) -> ThreatIntelConsumerAction {
    match consumer {
        ThreatIntelConsumerKind::ShadowOnly => ThreatIntelConsumerAction::ShadowOnly,
        ThreatIntelConsumerKind::RawCompatibility => {
            ThreatIntelConsumerAction::RawCompatibilityOnly
        }
        ThreatIntelConsumerKind::AdvisoryCache => ThreatIntelConsumerAction::SuppressAction,
        ThreatIntelConsumerKind::Enforcement => match decision {
            Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::Actionable(_)) => {
                ThreatIntelConsumerAction::PermitAction
            }
            Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::Deferred(_)) => {
                match deferred_mode {
                    ThreatIntelDeferredMode::FailOpenNoAction => {
                        ThreatIntelConsumerAction::SuppressAction
                    }
                    ThreatIntelDeferredMode::FailClosedNoAction => {
                        ThreatIntelConsumerAction::SuppressAction
                    }
                    ThreatIntelDeferredMode::ShadowOnly => ThreatIntelConsumerAction::ShadowOnly,
                }
            }
            Some(_) => ThreatIntelConsumerAction::SuppressAction,
            None => ThreatIntelConsumerAction::SuppressAction,
        },
    }
}

/// Result of evaluating the enforcement policy gate for an incoming threat.
///
/// Carries both the consumer action (permit/suppress) and the underlying
/// policy decision so callers can record accurate suppression metrics.
#[derive(Debug, Clone)]
struct IncomingThreatPolicyGate {
    action: ThreatIntelConsumerAction,
    decision: Option<crate::threat_intel_policy::ThreatIntelPolicyDecision>,
}

/// Record the correct suppression metric based on the actual policy decision.
fn record_enforcement_suppression_metric(
    decision: &Option<crate::threat_intel_policy::ThreatIntelPolicyDecision>,
) {
    match decision {
        None => crate::stubs::metrics::record_threat_intel_enforcement_suppressed_not_configured(),
        Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::AdvisoryOnly(_)) => {
            crate::stubs::metrics::record_threat_intel_enforcement_suppressed_advisory_only();
        }
        Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::NotActionable(_)) => {
            crate::stubs::metrics::record_threat_intel_enforcement_suppressed_not_actionable();
        }
        Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::Deferred(_)) => {
            crate::stubs::metrics::record_threat_intel_enforcement_suppressed_deferred();
        }
        Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::Actionable(_)) => {
            // Do not record suppression for permitted decisions.
        }
    }
}

pub struct ThreatIntelligenceManager {
    config: Arc<ThreatIntelligenceConfigInternal>,
    block_store: Arc<dyn BlockStoreApi + Send + Sync>,
    reputation: Arc<ReputationManager>,
    node_id: String,
    node_role: MeshNodeRole,
    signer: Option<Arc<crate::protocol::MeshMessageSigner>>,
    local_version: RwLock<u64>,
    indicators: RwLock<HashMap<String, ThreatIndicatorEntry>>,
    pending_announces: RwLock<VecDeque<ThreatIndicator>>,
    mesh_sender: Arc<RwLock<Option<mpsc::Sender<MeshMessage>>>>,
    transport: Arc<RwLock<Option<Arc<crate::transport::MeshTransport>>>>,
    last_sync: RwLock<Instant>,
    global_node_ips: RwLock<HashMap<String, IpAddr>>,
    persistence_path: Option<std::path::PathBuf>,
    seen_announces: moka::sync::Cache<String, bool>,
    hot_threats: RwLock<bloomfilter::Bloom<IpAddr>>,
    policy_context: RwLock<Option<ThreatIntelPolicyContext>>,
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
        block_store: Arc<dyn BlockStoreApi + Send + Sync>,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::protocol::MeshMessageSigner>>,
    ) -> Self {
        Self::new_inner(config, block_store, node_id, node_role, signer, None)
    }

    pub fn new_for_standalone(
        config: ThreatIntelligenceConfigInternal,
        block_store: Arc<dyn BlockStoreApi + Send + Sync>,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::protocol::MeshMessageSigner>>,
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
        block_store: Arc<dyn BlockStoreApi + Send + Sync>,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::protocol::MeshMessageSigner>>,
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
            policy_context: RwLock::new(None),
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

    pub fn set_transport(&self, transport: Arc<crate::transport::MeshTransport>) {
        let mut t = self.transport.write();
        *t = Some(transport);
    }

    /// Injection point for the optional policy context.
    ///
    /// When `None` (the default), configured evaluation and policy-composed
    /// lookups fall back to legacy raw paths or return `None`.
    pub fn set_policy_context(&self, ctx: Option<ThreatIntelPolicyContext>) {
        *self.policy_context.write() = ctx;
    }

    /// Returns a clone of the current policy context, if set.
    fn policy_context(&self) -> Option<ThreatIntelPolicyContext> {
        self.policy_context.read().clone()
    }

    pub fn from_external_config(
        config: ThreatIntelligenceConfig,
        block_store: Arc<dyn BlockStoreApi + Send + Sync>,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::protocol::MeshMessageSigner>>,
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
            timestamp: synvoid_utils::safe_unix_timestamp(),
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
        let now = synvoid_utils::safe_unix_timestamp();
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

    pub fn get_block_store(&self) -> Arc<dyn BlockStoreApi + Send + Sync> {
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
        let now = synvoid_utils::safe_unix_timestamp();

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

    pub fn announce_local_unblock(
        &self,
        target_kind: synvoid_core::block_store::BlockTargetKind,
        identifier: &str,
        site_scope: &str,
        provenance: synvoid_core::block_store::BlockProvenance,
    ) {
        let now = synvoid_utils::safe_unix_timestamp();
        let mut event = synvoid_core::block_store::BlocklistEvent::unblock_ip(
            identifier,
            site_scope,
            provenance.clone(),
            now,
        );
        if matches!(
            target_kind,
            synvoid_core::block_store::BlockTargetKind::MeshId
        ) {
            event = synvoid_core::block_store::BlocklistEvent::unblock_mesh_id(
                identifier, site_scope, provenance, now,
            );
        }
        let event_id = event.generate_event_id();
        event = event
            .with_source_node(self.node_id.clone())
            .with_event_id(event_id);

        let op_u32 = crate::blocklist_event::operation_to_u32(event.operation);
        let tk_u32 = crate::blocklist_event::target_kind_to_u32(event.target_kind);

        let gossip_msg = MeshMessage::BlocklistEventGossip {
            event_id: event.event_id.as_deref().unwrap_or("").into(),
            source_node: self.node_id.clone().into(),
            timestamp: now,
            operation: op_u32,
            target_kind: tk_u32,
            identifier: identifier.into(),
            site_scope: site_scope.into(),
            reason: None,
            provenance_kind: crate::blocklist_event::provenance_kind_to_u32(event.provenance.kind),
            provenance_source: event.provenance.source.clone().map(|s| s.into()),
            ttl_secs: None,
            version: None,
            signature: Vec::new(),
            signer_public_key: None,
        };

        let sender = self.mesh_sender.read().clone();
        if let Some(tx) = sender {
            let _ = tx.try_send(gossip_msg);
            tracing::debug!(
                "Announced local unblock for {:?} {} to mesh",
                target_kind,
                identifier
            );
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
        let now = synvoid_utils::safe_unix_timestamp();

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
            self.block_store.block_ip_with_provenance(
                ip,
                &reason,
                ttl,
                site_scope,
                BlockProvenance {
                    kind: BlockProvenanceKind::LocalHoneypot,
                    source: Some(format!("announce_local_block:{}", ip)),
                },
            );
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
        let now = synvoid_utils::safe_unix_timestamp();

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
        let now = synvoid_utils::safe_unix_timestamp();

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

        let value = match synvoid_utils::serialization::serialize(indicator) {
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
        signer: Option<&Arc<crate::protocol::MeshMessageSigner>>,
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

        let now = synvoid_utils::safe_unix_timestamp();

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

        // Policy gate: evaluate actionability before any enforcement mutation.
        // Mesh-sourced enforcement requires canonical trust; advisory-only DHT
        // records must not cause block/rate-limit/suspicious mutations.
        let policy_gate =
            self.evaluate_incoming_threat_policy(&indicator.indicator_value, indicator.threat_type);
        let enforcement_action = policy_gate.action;

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

                    if enforcement_action == ThreatIntelConsumerAction::PermitAction {
                        let banned = self.block_store.block_ip_with_provenance(
                            ip,
                            &format!("mesh:{}:{}", from_node, indicator.reason),
                            indicator.ttl_seconds,
                            &indicator.site_scope,
                            BlockProvenance {
                                kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
                                source: Some(from_node.to_string()),
                            },
                        );

                        if banned {
                            tracing::info!(
                                "Applied mesh block from {}: {} (reason: {}, TTL: {}s)",
                                from_node,
                                ip,
                                indicator.reason,
                                indicator.ttl_seconds
                            );
                            crate::stubs::metrics::record_threat_intel_enforcement_permitted();
                        }
                    } else {
                        tracing::debug!(
                            indicator = %indicator.indicator_value,
                            threat_type = ?indicator.threat_type,
                            from_node = from_node,
                            action = ?enforcement_action,
                            "Enforcement gate suppressed IpBlock mutation"
                        );
                        record_enforcement_suppression_metric(&policy_gate.decision);
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
                    if enforcement_action == ThreatIntelConsumerAction::PermitAction {
                        self.apply_rate_limit_mesh_action_after_policy_permit(
                            &indicator, from_node,
                        );
                        crate::stubs::metrics::record_threat_intel_enforcement_permitted();
                    } else {
                        tracing::debug!(
                            indicator = %indicator.indicator_value,
                            threat_type = ?indicator.threat_type,
                            from_node = from_node,
                            action = ?enforcement_action,
                            "Enforcement gate suppressed RateLimitViolation mutation"
                        );
                        record_enforcement_suppression_metric(&policy_gate.decision);
                    }
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
                    if enforcement_action == ThreatIntelConsumerAction::PermitAction {
                        self.apply_suspicious_mesh_action_after_policy_permit(
                            &indicator, from_node,
                        );
                        crate::stubs::metrics::record_threat_intel_enforcement_permitted();
                    } else {
                        tracing::debug!(
                            indicator = %indicator.indicator_value,
                            threat_type = ?indicator.threat_type,
                            from_node = from_node,
                            action = ?enforcement_action,
                            "Enforcement gate suppressed SuspiciousActivity mutation"
                        );
                        record_enforcement_suppression_metric(&policy_gate.decision);
                    }
                }
            }
            ThreatType::AsnBlock => {
                if let Ok(asn) = indicator.indicator_value.parse::<u32>() {
                    // No enforcement mutation — ASN block is observational only in this path.
                    tracing::info!(
                        "Received mesh ASN block advisory from {}: AS{} (reason: {}, TTL: {}s) — ASN enforcement not wired in this path",
                        from_node,
                        asn,
                        indicator.reason,
                        indicator.ttl_seconds
                    );
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
                    if enforcement_action == ThreatIntelConsumerAction::PermitAction {
                        let reqs = indicator.rate_limit_requests.unwrap_or(50);
                        let window = indicator.rate_limit_window_secs.unwrap_or(60);
                        self.block_store.block_ip_with_provenance(
                            ip,
                            &format!("mesh:{}:ip_throttle:{}r/{}s", from_node, reqs, window),
                            indicator.ttl_seconds,
                            &indicator.site_scope,
                            BlockProvenance {
                                kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
                                source: Some(from_node.to_string()),
                            },
                        );
                        tracing::info!(
                            "Applied mesh IP throttle from {}: {} ({} reqs/{}s, TTL: {}s)",
                            from_node,
                            ip,
                            reqs,
                            window,
                            indicator.ttl_seconds
                        );
                        crate::stubs::metrics::record_threat_intel_enforcement_permitted();
                    } else {
                        tracing::debug!(
                            indicator = %indicator.indicator_value,
                            threat_type = ?indicator.threat_type,
                            from_node = from_node,
                            action = ?enforcement_action,
                            "Enforcement gate suppressed IpThrottle mutation"
                        );
                        record_enforcement_suppression_metric(&policy_gate.decision);
                    }
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

    /// **Not for enforcement** — compatibility / low-level DHT lookup API.
    ///
    /// Returns the indicator directly from the DHT record store without any
    /// policy evaluation. **Must not be used by enforcement consumers** unless
    /// wrapped by an explicit policy-composed gate. Use
    /// [`lookup_threat_indicator_policy_composed`] or
    /// [`lookup_threat_indicator_policy_strict`] for actionability-sensitive reads.
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
            Err(_) => match synvoid_utils::serialization::deserialize(&record.value) {
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

    /// **Not for enforcement** — compatibility / low-level local lookup API.
    ///
    /// Returns the indicator directly from the in-memory store without any
    /// policy evaluation. **Must not be used by enforcement consumers** unless
    /// wrapped by an explicit policy-composed gate. Use
    /// [`lookup_local_indicator_policy_composed`] or
    /// [`lookup_local_indicator_policy_strict`] for actionability-sensitive reads.
    pub fn lookup_local_indicator(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> Option<ThreatIndicator> {
        let key = make_indicator_key(indicator_value, threat_type);
        let indicators = self.indicators.read();
        indicators.get(&key).map(|entry| entry.indicator.clone())
    }

    /// **Not for enforcement** — compatibility / low-level IP convenience wrapper.
    ///
    /// Delegates to [`lookup_local_indicator`](Self::lookup_local_indicator)
    /// with `ThreatType::IpBlock`. **Must not be used by enforcement consumers**
    /// unless wrapped by an explicit policy-composed gate. Use
    /// [`lookup_local_indicator_by_ip_policy_composed`] or
    /// [`lookup_local_indicator_by_ip_policy_strict`] for actionability-sensitive reads.
    pub fn lookup_local_indicator_by_ip(&self, ip: &str) -> Option<ThreatIndicator> {
        self.lookup_local_indicator(ip, ThreatType::IpBlock)
    }

    /// Evaluate a threat indicator's actionability using the policy composition
    /// helper (Iteration 19).
    ///
    /// This is the first consumer migration pass for the threat-intel policy
    /// layer. It composes advisory DHT observations with canonical Raft trust
    /// to produce an explicit actionability decision.
    ///
    /// # Arguments
    ///
    /// * `canonical` — Canonical trust reader (Raft-derived snapshot).
    /// * `advisory` — Advisory DHT record source.
    /// * `indicator_value` — The indicator value (e.g., an IP address).
    /// * `threat_type` — The threat type classification.
    ///
    /// # Policy Mapping
    ///
    /// - `Actionable` → indicator is advisory-present + canonical-trusted.
    /// - `AdvisoryOnly` → advisory present but canonical trust absent (never actionable).
    /// - `NotActionable` → advisory missing/expired or canonical explicitly not trusted.
    /// - `Deferred` → one or both sources unavailable or unknown.
    ///
    /// The old raw lookup paths (`lookup_local_indicator`,
    /// `lookup_local_indicator_by_ip`, `lookup_threat_indicator_in_dht`) remain
    /// available for comparison and fallback.
    pub fn evaluate_indicator_actionability(
        &self,
        canonical: &dyn crate::canonical::CanonicalTrustReader,
        advisory: &dyn crate::dht::advisory_source::AdvisoryRecordSource,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> crate::threat_intel_policy::ThreatIntelPolicyDecision {
        let advisory_key = make_indicator_key(indicator_value, threat_type);
        crate::threat_intel_policy::evaluate_threat_intel_policy(
            canonical,
            advisory,
            indicator_value,
            &advisory_key,
        )
    }

    /// Evaluate a threat indicator using the injected policy context.
    ///
    /// Returns `None` if no policy context is configured (callers should fall
    /// back to legacy raw paths). Otherwise delegates to the manual evaluation
    /// method using the stored canonical and advisory readers.
    pub fn evaluate_indicator_actionability_configured(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> Option<crate::threat_intel_policy::ThreatIntelPolicyDecision> {
        let ctx = self.policy_context()?;
        Some(self.evaluate_indicator_actionability(
            ctx.canonical(),
            ctx.advisory(),
            indicator_value,
            threat_type,
        ))
    }

    /// Preferred policy-composed threat indicator lookup for new
    /// actionability-sensitive reads.
    ///
    /// Requires a configured policy context; without one, falls back to the
    /// legacy raw DHT lookup. When configured, the policy decision gates the
    /// result:
    ///
    /// - `Actionable` → returns the indicator from the legacy raw DHT lookup.
    /// - `AdvisoryOnly` / `NotActionable` / `Deferred` → returns `None`.
    pub fn lookup_threat_indicator_policy_composed(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> Option<ThreatIndicator> {
        let ctx = match self.policy_context() {
            Some(ctx) => ctx,
            None => return self.lookup_threat_indicator_in_dht(indicator_value, threat_type),
        };

        let decision = self.evaluate_indicator_actionability(
            ctx.canonical(),
            ctx.advisory(),
            indicator_value,
            threat_type,
        );

        if Self::is_policy_actionable(&decision) {
            self.lookup_threat_indicator_in_dht(indicator_value, threat_type)
        } else {
            tracing::debug!(
                indicator = indicator_value,
                threat_type = ?threat_type,
                decision = ?decision,
                "policy-composed lookup: not actionable, returning None"
            );
            None
        }
    }

    /// Preferred policy-composed local threat indicator lookup for new
    /// actionability-sensitive reads (Iteration 21).
    ///
    /// Requires a configured policy context; without one, falls back to the
    /// legacy raw local lookup. When configured, the policy decision gates the
    /// result:
    ///
    /// - `Actionable` → returns the indicator from the legacy raw local lookup.
    /// - `AdvisoryOnly` / `NotActionable` / `Deferred` → returns `None`.
    pub fn lookup_local_indicator_policy_composed(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> Option<ThreatIndicator> {
        let ctx = match self.policy_context() {
            Some(ctx) => ctx,
            None => return self.lookup_local_indicator(indicator_value, threat_type),
        };

        let decision = self.evaluate_indicator_actionability(
            ctx.canonical(),
            ctx.advisory(),
            indicator_value,
            threat_type,
        );

        if Self::is_policy_actionable(&decision) {
            self.lookup_local_indicator(indicator_value, threat_type)
        } else {
            tracing::debug!(
                indicator = indicator_value,
                threat_type = ?threat_type,
                decision = ?decision,
                "policy-composed local lookup: not actionable, returning None"
            );
            None
        }
    }

    /// Preferred policy-composed IP convenience wrapper for new
    /// actionability-sensitive reads (Iteration 21).
    ///
    /// Delegates to
    /// [`lookup_local_indicator_policy_composed`](Self::lookup_local_indicator_policy_composed)
    /// with `ThreatType::IpBlock`.
    pub fn lookup_local_indicator_by_ip_policy_composed(
        &self,
        ip: &str,
    ) -> Option<ThreatIndicator> {
        self.lookup_local_indicator_policy_composed(ip, ThreatType::IpBlock)
    }

    /// Returns `true` when the policy decision is `Actionable`.
    fn is_policy_actionable(
        decision: &crate::threat_intel_policy::ThreatIntelPolicyDecision,
    ) -> bool {
        matches!(
            decision,
            crate::threat_intel_policy::ThreatIntelPolicyDecision::Actionable(_)
        )
    }

    /// Strict policy-composed DHT lookup for enforcement consumers.
    ///
    /// Unlike [`lookup_threat_indicator_policy_composed`], this method
    /// returns `None` when no policy context is configured, rather than
    /// falling back to the legacy raw DHT lookup.
    ///
    /// - `Some(Actionable)` → returns the indicator from the raw DHT lookup.
    /// - `Some(non-actionable)` → returns `None`.
    /// - `None` policy context → returns `None`.
    pub fn lookup_threat_indicator_policy_strict(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> Option<ThreatIndicator> {
        let ctx = self.policy_context()?;

        let decision = self.evaluate_indicator_actionability(
            ctx.canonical(),
            ctx.advisory(),
            indicator_value,
            threat_type,
        );

        if Self::is_policy_actionable(&decision) {
            self.lookup_threat_indicator_in_dht(indicator_value, threat_type)
        } else {
            tracing::debug!(
                indicator = indicator_value,
                threat_type = ?threat_type,
                decision = ?decision,
                "strict policy-composed DHT lookup: not actionable, returning None"
            );
            None
        }
    }

    /// Strict policy-composed local lookup for enforcement consumers.
    ///
    /// Unlike [`lookup_local_indicator_policy_composed`], this method
    /// returns `None` when no policy context is configured, rather than
    /// falling back to the legacy raw local lookup.
    ///
    /// - `Some(Actionable)` → returns the indicator from the raw local lookup.
    /// - `Some(non-actionable)` → returns `None`.
    /// - `None` policy context → returns `None`.
    pub fn lookup_local_indicator_policy_strict(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> Option<ThreatIndicator> {
        let ctx = self.policy_context()?;

        let decision = self.evaluate_indicator_actionability(
            ctx.canonical(),
            ctx.advisory(),
            indicator_value,
            threat_type,
        );

        if Self::is_policy_actionable(&decision) {
            self.lookup_local_indicator(indicator_value, threat_type)
        } else {
            tracing::debug!(
                indicator = indicator_value,
                threat_type = ?threat_type,
                decision = ?decision,
                "strict policy-composed local lookup: not actionable, returning None"
            );
            None
        }
    }

    /// Strict policy-composed IP convenience wrapper for enforcement consumers.
    ///
    /// Delegates to [`lookup_local_indicator_policy_strict`] with `ThreatType::IpBlock`.
    pub fn lookup_local_indicator_by_ip_policy_strict(&self, ip: &str) -> Option<ThreatIndicator> {
        self.lookup_local_indicator_policy_strict(ip, ThreatType::IpBlock)
    }

    /// Evaluate incoming mesh threat with the enforcement policy gate.
    ///
    /// Returns an [`IncomingThreatPolicyGate`] carrying both the consumer
    /// action (permit/suppress) and the underlying policy decision so callers
    /// can record accurate suppression metrics.
    fn evaluate_incoming_threat_policy(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> IncomingThreatPolicyGate {
        let decision =
            self.evaluate_indicator_actionability_configured(indicator_value, threat_type);
        let action = classify_consumer_action(
            decision.as_ref(),
            ThreatIntelConsumerKind::Enforcement,
            ThreatIntelDeferredMode::FailOpenNoAction,
        );
        IncomingThreatPolicyGate { action, decision }
    }

    /// Shadow evaluation of a threat indicator for diagnostics and metrics.
    ///
    /// This method evaluates policy composition without changing enforcement
    /// behavior. It returns a `ThreatIntelPolicyShadowDecision` suitable for
    /// admin diagnostics, structured logging, and metrics counters.
    ///
    /// **This is a shadow/observability consumer only.** It does not block
    /// traffic, mutate enforcement state, or affect request handling.
    pub fn evaluate_indicator_policy_shadow(
        &self,
        indicator_value: &str,
        threat_type: ThreatType,
    ) -> crate::threat_intel_policy::ThreatIntelPolicyShadowDecision {
        let threat_type_str = format!("{:?}", threat_type);
        let decision =
            self.evaluate_indicator_actionability_configured(indicator_value, threat_type);

        // Check raw lookup for disagreement classification
        let raw_present = self
            .lookup_local_indicator(indicator_value, threat_type)
            .is_some();

        // Build shadow DTO
        let shadow = crate::threat_intel_policy::threat_intel_policy_shadow_decision(
            indicator_value,
            &threat_type_str,
            decision.as_ref(),
            Some(raw_present),
        );

        // Increment metrics by decision class
        use crate::threat_intel_policy::ThreatIntelPolicyDecisionClass;
        match shadow.decision_class {
            ThreatIntelPolicyDecisionClass::Actionable => {
                crate::stubs::metrics::record_threat_intel_policy_shadow_actionable();
            }
            ThreatIntelPolicyDecisionClass::AdvisoryOnly => {
                crate::stubs::metrics::record_threat_intel_policy_shadow_advisory_only();
            }
            ThreatIntelPolicyDecisionClass::NotActionable => {
                crate::stubs::metrics::record_threat_intel_policy_shadow_not_actionable();
            }
            ThreatIntelPolicyDecisionClass::Deferred => {
                crate::stubs::metrics::record_threat_intel_policy_shadow_deferred();
            }
            ThreatIntelPolicyDecisionClass::NotConfigured => {
                crate::stubs::metrics::record_threat_intel_policy_shadow_not_configured();
            }
            ThreatIntelPolicyDecisionClass::Error => {}
        }

        // Track canonical unavailability specifically
        if matches!(
            decision,
            Some(
                crate::threat_intel_policy::ThreatIntelPolicyDecision::Deferred(
                    crate::threat_intel_policy::ThreatIntelPolicyDeferReason::CanonicalUnavailable
                )
            )
        ) {
            crate::stubs::metrics::record_threat_intel_policy_shadow_canonical_unavailable();
        }

        // Track advisory missing specifically
        if matches!(
            decision,
            Some(
                crate::threat_intel_policy::ThreatIntelPolicyDecision::NotActionable(
                    crate::threat_intel_policy::ThreatIntelPolicyRejectReason::AdvisoryMissing
                )
            )
        ) {
            crate::stubs::metrics::record_threat_intel_policy_shadow_advisory_missing();
        }

        // Track raw vs composed disagreement
        if let Some(disagreement) =
            crate::threat_intel_policy::classify_shadow_disagreement(raw_present, decision.as_ref())
        {
            crate::stubs::metrics::record_threat_intel_policy_shadow_raw_disagreement();
            tracing::debug!(
                indicator = indicator_value,
                threat_type = ?threat_type,
                disagreement = ?disagreement,
                "shadow evaluation: raw/composed disagreement detected"
            );
        }

        shadow
    }

    pub fn is_mesh_available(&self) -> bool {
        self.transport.read().is_some()
    }

    pub fn get_node_role(&self) -> MeshNodeRole {
        self.node_role
    }

    /// Apply a mesh-sourced rate limit action to the block store.
    ///
    /// # Preconditions
    ///
    /// Caller MUST have verified `ThreatIntelConsumerAction::PermitAction`
    /// via the enforcement policy gate before calling this helper.
    /// This helper does not re-check the policy — it trusts the caller.
    fn apply_rate_limit_mesh_action_after_policy_permit(
        &self,
        indicator: &ThreatIndicator,
        from_node: &str,
    ) {
        if let Ok(ip) = indicator.indicator_value.parse::<IpAddr>() {
            let reqs = indicator.rate_limit_requests.unwrap_or(100);
            let window = indicator.rate_limit_window_secs.unwrap_or(60);

            self.block_store.block_ip_with_provenance(
                ip,
                &format!("mesh:{}:ratelimit:{}r/{}s", from_node, reqs, window),
                indicator.ttl_seconds,
                &indicator.site_scope,
                BlockProvenance {
                    kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
                    source: Some(from_node.to_string()),
                },
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

    /// Apply a mesh-sourced suspicious activity block to the block store.
    ///
    /// # Preconditions
    ///
    /// Caller MUST have verified `ThreatIntelConsumerAction::PermitAction`
    /// via the enforcement policy gate before calling this helper.
    /// This helper does not re-check the policy — it trusts the caller.
    fn apply_suspicious_mesh_action_after_policy_permit(
        &self,
        indicator: &ThreatIndicator,
        from_node: &str,
    ) {
        if let Ok(ip) = indicator.indicator_value.parse::<IpAddr>() {
            let severity_ttl = match indicator.severity {
                ThreatSeverity::Critical => 7200,
                ThreatSeverity::High => 3600,
                ThreatSeverity::Medium => 1800,
                ThreatSeverity::Low => 900,
                ThreatSeverity::Unspecified => 300,
            };

            self.block_store.block_ip_with_provenance(
                ip,
                &format!("mesh:{}:suspicious", from_node),
                severity_ttl,
                &indicator.site_scope,
                BlockProvenance {
                    kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
                    source: Some(from_node.to_string()),
                },
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
        signer: Option<&Arc<crate::protocol::MeshMessageSigner>>,
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
        let now = synvoid_utils::safe_unix_timestamp();

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

                    let signer = crate::protocol::MeshMessageSigner::new(pk_bytes);
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
        if let Ok(indicator) = synvoid_utils::serialization::deserialize(record_value) {
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
            let tree = crate::dht::merkle::MerkleTree::from_records(&records);
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
    pub reputation_stats: Vec<crate::reputation::PeerReputationStats>,
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
        signer: Option<&Arc<crate::protocol::MeshMessageSigner>>,
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
                        let tree = crate::dht::merkle::MerkleTree::from_records(&records);
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
        let now = synvoid_utils::safe_unix_timestamp();

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
        let now = synvoid_utils::safe_unix_timestamp();
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
            policy_context: RwLock::new(self.policy_context.read().clone()),
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
        let block_store = Arc::new(crate::stubs::block_store::BlockStore::new(
            false,
            None,
            Default::default(),
        ));
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

    // ---------------------------------------------------------------------------
    // Iteration 19: evaluate_indicator_actionability tests
    // ---------------------------------------------------------------------------

    use crate::canonical::{
        CanonicalFreshness, CanonicalTrustDecision, CanonicalTrustReader, CanonicalTrustReason,
    };
    use crate::dht::advisory_source::{
        AdvisoryFreshness, AdvisoryRecord, AdvisoryRecordLookup, AdvisoryRecordSource,
        AdvisoryRecordStatus,
    };
    use crate::threat_intel_policy::{
        ThreatIntelPolicyDecision, ThreatIntelPolicyDeferReason, ThreatIntelPolicyEvidence,
        ThreatIntelPolicyRejectReason,
    };
    use std::collections::HashMap;

    #[derive(Debug, Default, Clone)]
    struct TestAdvisorySource {
        records: HashMap<String, AdvisoryRecord>,
        unavailable: bool,
    }

    impl TestAdvisorySource {
        fn new() -> Self {
            Self::default()
        }

        fn unavailable() -> Self {
            Self {
                unavailable: true,
                ..Default::default()
            }
        }

        fn with_record(mut self, key: &str, record: AdvisoryRecord) -> Self {
            self.records.insert(key.to_string(), record);
            self
        }
    }

    impl AdvisoryRecordSource for TestAdvisorySource {
        fn get_advisory_record(&self, key: &str) -> AdvisoryRecordLookup {
            if self.unavailable {
                return AdvisoryRecordLookup::Unavailable;
            }
            match self.records.get(key) {
                Some(r) => {
                    let now = synvoid_utils::safe_unix_timestamp();
                    if r.ttl_seconds > 0 && now > r.timestamp + r.ttl_seconds {
                        AdvisoryRecordLookup::Expired
                    } else {
                        AdvisoryRecordLookup::Present(r.clone())
                    }
                }
                None => AdvisoryRecordLookup::Missing,
            }
        }

        fn get_advisory_records_by_prefix(
            &self,
            _prefix: &str,
            _limit: usize,
        ) -> Vec<AdvisoryRecord> {
            vec![]
        }
    }

    #[derive(Debug, Clone)]
    struct TestCanonicalReader {
        trust: HashMap<String, CanonicalTrustDecision>,
        default_freshness: CanonicalFreshness,
    }

    impl TestCanonicalReader {
        fn new(freshness: CanonicalFreshness) -> Self {
            Self {
                trust: HashMap::new(),
                default_freshness: freshness,
            }
        }

        fn with_trust(mut self, intel_id: &str, decision: CanonicalTrustDecision) -> Self {
            self.trust.insert(intel_id.to_string(), decision);
            self
        }
    }

    impl CanonicalTrustReader for TestCanonicalReader {
        fn freshness(&self) -> CanonicalFreshness {
            self.default_freshness
        }

        fn is_global_node_authorized(&self, _: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.default_freshness,
                reason: CanonicalTrustReason::UnsupportedDecisionType,
            }
        }

        fn is_org_key_trusted(&self, _: &str, _: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.default_freshness,
                reason: CanonicalTrustReason::UnsupportedDecisionType,
            }
        }

        fn is_node_revoked(&self, _: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.default_freshness,
                reason: CanonicalTrustReason::UnsupportedDecisionType,
            }
        }

        fn node_revocation_status(&self, _: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.default_freshness,
                reason: CanonicalTrustReason::UnsupportedDecisionType,
            }
        }

        fn is_threat_intel_canonical(&self, intel_id: &str) -> CanonicalTrustDecision {
            self.trust
                .get(intel_id)
                .cloned()
                .unwrap_or(CanonicalTrustDecision::NotTrusted {
                    freshness: self.default_freshness,
                    reason: CanonicalTrustReason::NotPresentInCanonicalState,
                })
        }
    }

    fn test_advisory_record(key: &str) -> AdvisoryRecord {
        let now = synvoid_utils::safe_unix_timestamp();
        AdvisoryRecord {
            key: key.to_string(),
            value: b"test".to_vec(),
            source_node_id: "test-node".to_string(),
            timestamp: now,
            ttl_seconds: 3600,
            freshness: AdvisoryFreshness::Live,
            status: AdvisoryRecordStatus::Present,
            record_signature_valid: true,
        }
    }

    const TEST_IP: &str = "192.168.1.1";
    const TEST_KEY: &str = "threat_indicator:192.168.1.1:IpBlock";

    // Test 1: Actionable only when advisory present + canonical trusted.
    #[test]
    fn policy_actionable_only_when_both_present_and_trusted() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let decision = manager.evaluate_indicator_actionability(
            &canonical,
            &advisory,
            TEST_IP,
            ThreatType::IpBlock,
        );
        assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    }

    // Test 2: Advisory present but canonical unknown → not actionable (deferred).
    #[test]
    fn policy_advisory_present_canonical_unknown_not_actionable() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live);

        let decision = manager.evaluate_indicator_actionability(
            &canonical,
            &advisory,
            TEST_IP,
            ThreatType::IpBlock,
        );
        assert!(matches!(
            decision,
            ThreatIntelPolicyDecision::Deferred(ThreatIntelPolicyDeferReason::CanonicalUnknown)
        ));
    }

    // Test 3: Advisory missing → not actionable.
    #[test]
    fn policy_advisory_missing_not_actionable() {
        let manager = create_test_manager();
        let advisory = TestAdvisorySource::new();
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let decision = manager.evaluate_indicator_actionability(
            &canonical,
            &advisory,
            TEST_IP,
            ThreatType::IpBlock,
        );
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::AdvisoryMissing
            )
        );
    }

    // Test 4: Canonical explicitly not trusted → not actionable.
    #[test]
    fn policy_canonical_not_trusted_not_actionable() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Live,
                reason: CanonicalTrustReason::Revoked,
            },
        );

        let decision = manager.evaluate_indicator_actionability(
            &canonical,
            &advisory,
            TEST_IP,
            ThreatType::IpBlock,
        );
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::CanonicalNotTrusted
            )
        );
    }

    // Test 5: Canonical unavailable → deferred (conservative).
    #[test]
    fn policy_canonical_unavailable_deferred() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Unavailable);

        let decision = manager.evaluate_indicator_actionability(
            &canonical,
            &advisory,
            TEST_IP,
            ThreatType::IpBlock,
        );
        assert!(matches!(
            decision,
            ThreatIntelPolicyDecision::Deferred(ThreatIntelPolicyDeferReason::CanonicalUnavailable)
        ));
    }

    // Test 6: Legacy raw lookup path remains available and behaves as before.
    #[test]
    fn legacy_lookup_path_still_works() {
        let manager = create_test_manager();

        // Use a fresh indicator with current timestamp to avoid expiry.
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };

        // Register peer so reputation check passes.
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);

        // Insert via the normal path.
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        // Legacy lookup still returns the indicator.
        let found = manager.lookup_local_indicator(TEST_IP, ThreatType::IpBlock);
        assert!(found.is_some());
        assert_eq!(found.unwrap().indicator_value, TEST_IP);

        // Policy path works independently with the same indicator value.
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );
        let decision = manager.evaluate_indicator_actionability(
            &canonical,
            &advisory,
            TEST_IP,
            ThreatType::IpBlock,
        );
        assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    }

    // Test 7: Comparison — advisory-only records never become actionable.
    #[test]
    fn comparison_advisory_only_never_actionable() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical_no_trust = TestCanonicalReader::new(CanonicalFreshness::Live);

        let decision = manager.evaluate_indicator_actionability(
            &canonical_no_trust,
            &advisory,
            TEST_IP,
            ThreatType::IpBlock,
        );

        // Must NOT be Actionable — advisory-only is never actionable.
        assert!(
            !matches!(decision, ThreatIntelPolicyDecision::Actionable(_)),
            "advisory-only records must never be actionable, got: {:?}",
            decision
        );
    }

    // Test 8: No DHT, Raft, or networking required — pure static sources.
    #[test]
    fn policy_evaluation_requires_no_dht_raft_or_networking() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let decision = manager.evaluate_indicator_actionability(
            &canonical,
            &advisory,
            TEST_IP,
            ThreatType::IpBlock,
        );
        assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    }

    #[test]
    fn test_signable_content_matches_feed_client() {
        use crate::stubs::waf_stub::threat_intel::feed_client::ThreatFeedIndicator;
        use crate::stubs::waf_stub::threat_intel::feed_client::ThreatFeedPayload;

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
            crate::stubs::waf_stub::threat_intel::feed_client::ThreatFeedPayload::get_signable_content(&payload);

        assert_eq!(
            our_content.into_bytes(),
            feed_client_content,
            "Signable content must match ThreatFeedClient format"
        );
    }

    // ---------------------------------------------------------------------------
    // Iteration 20: ThreatIntelPolicyContext injection tests
    // ---------------------------------------------------------------------------

    // Test 9: Default manager has no policy context; legacy lookup still works.
    #[test]
    fn iteration20_default_manager_has_no_policy_context() {
        let manager = create_test_manager();
        assert!(
            manager.policy_context().is_none(),
            "default manager must have no policy context"
        );

        // Configured evaluation returns None when no context is set.
        let result =
            manager.evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock);
        assert!(result.is_none());
    }

    // Test 10: set_policy_context enables configured evaluation.
    #[test]
    fn iteration20_set_policy_context_enables_configured_evaluation() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let ctx = ThreatIntelPolicyContext::new(Arc::new(canonical), Arc::new(advisory));
        manager.set_policy_context(Some(ctx));

        assert!(manager.policy_context().is_some());
        let decision = manager
            .evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock)
            .expect("should have policy context");
        assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    }

    // Test 11: Configured actionability returns Actionable only when advisory
    // present and canonical trusted.
    #[test]
    fn iteration20_configured_actionable_only_when_both_present_and_trusted() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let decision = manager
            .evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock)
            .unwrap();
        assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    }

    // Test 12: Configured actionability returns non-actionable/deferred for
    // advisory-only, advisory missing, canonical not trusted, canonical unavailable.
    #[test]
    fn iteration20_configured_not_actionable_for_advisory_only() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical_no_trust = TestCanonicalReader::new(CanonicalFreshness::Live);

        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical_no_trust),
            Arc::new(advisory),
        )));

        let decision = manager
            .evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock)
            .unwrap();
        // Advisory-only → Deferred(CanonicalUnknown)
        assert!(!matches!(
            decision,
            ThreatIntelPolicyDecision::Actionable(_)
        ));
    }

    #[test]
    fn iteration20_configured_not_actionable_for_advisory_missing() {
        let manager = create_test_manager();
        let advisory = TestAdvisorySource::new(); // empty, no records
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let decision = manager
            .evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock)
            .unwrap();
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::AdvisoryMissing
            )
        );
    }

    #[test]
    fn iteration20_configured_not_actionable_for_canonical_not_trusted() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Live,
                reason: CanonicalTrustReason::Revoked,
            },
        );

        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let decision = manager
            .evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock)
            .unwrap();
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::CanonicalNotTrusted
            )
        );
    }

    #[test]
    fn iteration20_configured_deferred_for_canonical_unavailable() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Unavailable);

        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let decision = manager
            .evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock)
            .unwrap();
        assert!(matches!(
            decision,
            ThreatIntelPolicyDecision::Deferred(ThreatIntelPolicyDeferReason::CanonicalUnavailable)
        ));
    }

    // Test 13: Policy-composed read path returns result only for Actionable.
    #[test]
    fn iteration20_policy_composed_lookup_returns_indicator_for_actionable() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        // No transport/record store → DHT lookup returns None → policy-composed
        // returns None even for Actionable because raw DHT has no record.
        let result = manager.lookup_threat_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        assert!(
            result.is_none(),
            "no DHT record → policy-composed returns None even for Actionable"
        );
    }

    // Test 14: Policy-composed read path returns None for advisory-only.
    #[test]
    fn iteration20_policy_composed_lookup_returns_none_for_advisory_only() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical_no_trust = TestCanonicalReader::new(CanonicalFreshness::Live);

        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical_no_trust),
            Arc::new(advisory),
        )));

        let result = manager.lookup_threat_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        assert!(
            result.is_none(),
            "advisory-only → policy-composed must return None"
        );
    }

    // Test 15: Policy-composed read path falls back to legacy when no context.
    #[test]
    fn iteration20_policy_composed_lookup_falls_back_to_legacy_without_context() {
        let manager = create_test_manager();
        // No policy context set.
        let result = manager.lookup_threat_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        // No transport either → both paths return None.
        assert!(result.is_none());
    }

    // Test 16: Legacy raw path remains available and unchanged.
    #[test]
    fn iteration20_legacy_raw_path_remains_unchanged() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };

        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        let found = manager.lookup_local_indicator(TEST_IP, ThreatType::IpBlock);
        assert!(found.is_some());
        assert_eq!(found.unwrap().indicator_value, TEST_IP);

        // Also verify the manual method still works.
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );
        let decision = manager.evaluate_indicator_actionability(
            &canonical,
            &advisory,
            TEST_IP,
            ThreatType::IpBlock,
        );
        assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    }

    // Test 17: No DHT/Raft/networking required — pure static sources for configured path.
    #[test]
    fn iteration20_configured_evaluation_requires_no_dht_raft_or_networking() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let decision = manager
            .evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock)
            .unwrap();
        assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    }

    // ---------------------------------------------------------------------------
    // Iteration 21: lookup_local_indicator_policy_composed tests
    // ---------------------------------------------------------------------------

    // Test 18: No policy context → falls back to legacy local lookup.
    #[test]
    fn iteration21_no_context_falls_back_to_legacy_local_lookup() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        // No policy context → falls back to raw local lookup.
        let result = manager.lookup_local_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        assert!(
            result.is_some(),
            "no context must fall back to legacy local lookup"
        );
        assert_eq!(result.unwrap().indicator_value, TEST_IP);
    }

    // Test 19: Context with Actionable → returns the local indicator.
    #[test]
    fn iteration21_context_actionable_returns_local_indicator() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let result = manager.lookup_local_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        assert!(result.is_some(), "Actionable must return local indicator");
        assert_eq!(result.unwrap().indicator_value, TEST_IP);
    }

    // Test 20: Advisory present but canonical unknown → None.
    #[test]
    fn iteration21_advisory_present_canonical_unknown_returns_none() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live);
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let result = manager.lookup_local_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        assert!(
            result.is_none(),
            "advisory present + canonical unknown → None"
        );
    }

    // Test 21: Advisory missing → None.
    #[test]
    fn iteration21_advisory_missing_returns_none() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        let advisory = TestAdvisorySource::new();
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let result = manager.lookup_local_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        assert!(result.is_none(), "advisory missing → None");
    }

    // Test 22: Canonical not trusted → None.
    #[test]
    fn iteration21_canonical_not_trusted_returns_none() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Live,
                reason: CanonicalTrustReason::Revoked,
            },
        );
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let result = manager.lookup_local_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        assert!(result.is_none(), "canonical not trusted → None");
    }

    // Test 23: Canonical unavailable → None.
    #[test]
    fn iteration21_canonical_unavailable_returns_none() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Unavailable);
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let result = manager.lookup_local_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        assert!(result.is_none(), "canonical unavailable → None");
    }

    // Test 24: Raw lookup_local_indicator remains available.
    #[test]
    fn iteration21_raw_lookup_local_indicator_still_works() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        // Raw lookup always works regardless of policy context.
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Live,
                reason: CanonicalTrustReason::Revoked,
            },
        );
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let result = manager.lookup_local_indicator(TEST_IP, ThreatType::IpBlock);
        assert!(result.is_some(), "raw lookup must still work");
        assert_eq!(result.unwrap().indicator_value, TEST_IP);
    }

    // Test 25: IP convenience wrapper delegates to generic method.
    #[test]
    fn iteration21_ip_convenience_wrapper_delegates() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        // With Actionable context, IP wrapper returns the indicator.
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let result = manager.lookup_local_indicator_by_ip_policy_composed(TEST_IP);
        assert!(
            result.is_some(),
            "IP wrapper with Actionable must return indicator"
        );
        assert_eq!(result.unwrap().indicator_value, TEST_IP);

        // With non-actionable context, IP wrapper returns None.
        let advisory2 =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical_not_trusted = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Live,
                reason: CanonicalTrustReason::Revoked,
            },
        );
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical_not_trusted),
            Arc::new(advisory2),
        )));

        let result = manager.lookup_local_indicator_by_ip_policy_composed(TEST_IP);
        assert!(
            result.is_none(),
            "IP wrapper with non-actionable must return None"
        );
    }

    // Test 26: No DHT/Raft/networking required.
    #[test]
    fn iteration21_local_policy_composed_requires_no_dht_raft_or_networking() {
        let manager = create_test_manager();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);

        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let result = manager.lookup_local_indicator_policy_composed(TEST_IP, ThreatType::IpBlock);
        assert!(result.is_some());
    }

    // ---------------------------------------------------------------------------
    // Iteration 22: shared helper tests
    // ---------------------------------------------------------------------------

    #[test]
    fn iteration22_shared_helper_is_policy_actionable() {
        // Actionable → true
        assert!(ThreatIntelligenceManager::is_policy_actionable(
            &ThreatIntelPolicyDecision::Actionable(ThreatIntelPolicyEvidence {
                intel_id: "test".into(),
                advisory_key: "test".into(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            })
        ));
        // AdvisoryOnly → false
        assert!(!ThreatIntelligenceManager::is_policy_actionable(
            &ThreatIntelPolicyDecision::AdvisoryOnly(ThreatIntelPolicyEvidence {
                intel_id: "test".into(),
                advisory_key: "test".into(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            })
        ));
        // NotActionable → false
        assert!(!ThreatIntelligenceManager::is_policy_actionable(
            &ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::AdvisoryMissing
            )
        ));
        // Deferred → false
        assert!(!ThreatIntelligenceManager::is_policy_actionable(
            &ThreatIntelPolicyDecision::Deferred(
                ThreatIntelPolicyDeferReason::CanonicalUnavailable
            )
        ));
    }

    // ---------------------------------------------------------------------------
    // Iteration 33: Shadow evaluation helper tests
    // ---------------------------------------------------------------------------

    #[test]
    fn iteration33_shadow_helper_returns_not_configured_without_context() {
        let manager = create_test_manager();

        let shadow = manager.evaluate_indicator_policy_shadow("1.2.3.4", ThreatType::IpBlock);
        assert_eq!(
            shadow.decision_class,
            crate::threat_intel_policy::ThreatIntelPolicyDecisionClass::NotConfigured
        );
        assert!(!shadow.composed_actionable);
    }

    #[test]
    fn iteration33_shadow_helper_reports_actionable_with_context() {
        use crate::canonical::{
            CanonicalFreshness, CanonicalTrustDecision, CanonicalTrustReader,
            StaticCanonicalTrustReader,
        };
        use crate::dht::advisory_source::{
            AdvisoryFreshness, AdvisoryRecord, AdvisoryRecordLookup, AdvisoryRecordSource,
            AdvisoryRecordStatus, StaticAdvisoryRecordSource,
        };

        let mut canonical = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        canonical.threat_intel_ids.insert("1.2.3.4".to_string());

        let advisory_key = "threat_indicator:1.2.3.4:IpBlock";
        let advisory = StaticAdvisoryRecordSource::from_records(vec![AdvisoryRecord {
            key: advisory_key.to_string(),
            value: vec![],
            source_node_id: "test".to_string(),
            timestamp: crate::safe_unix_timestamp(),
            ttl_seconds: 300,
            freshness: AdvisoryFreshness::Live,
            status: AdvisoryRecordStatus::Present,
            record_signature_valid: true,
        }]);

        let ctx = crate::threat_intel::ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        );

        let manager = create_test_manager();
        manager.set_policy_context(Some(ctx));

        let shadow = manager.evaluate_indicator_policy_shadow("1.2.3.4", ThreatType::IpBlock);
        assert_eq!(
            shadow.decision_class,
            crate::threat_intel_policy::ThreatIntelPolicyDecisionClass::Actionable
        );
        assert!(shadow.composed_actionable);
        assert_eq!(shadow.indicator_value, "1.2.3.4");
        assert_eq!(shadow.threat_type, "IpBlock");
    }

    #[test]
    fn iteration33_shadow_helper_does_not_mutate_enforcement() {
        let manager = create_test_manager();

        // Shadow evaluation should not affect block store
        let _shadow = manager.evaluate_indicator_policy_shadow("1.2.3.4", ThreatType::IpBlock);
        let block_store = manager.get_block_store();
        assert!(!block_store.is_blocked(&"1.2.3.4".parse().unwrap(), "default"));
    }

    // ── Iteration 34: Consumer selection and enforcement gate tests ──

    #[test]
    fn iteration34_classify_consumer_action_shadow_only_always_suppresses() {
        // ShadowOnly consumers never permit action regardless of decision.
        let actionable = Some(ThreatIntelPolicyDecision::Actionable(
            ThreatIntelPolicyEvidence {
                intel_id: "test".to_string(),
                advisory_key: "key".to_string(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            },
        ));
        assert_eq!(
            classify_consumer_action(
                actionable.as_ref(),
                ThreatIntelConsumerKind::ShadowOnly,
                ThreatIntelDeferredMode::FailOpenNoAction,
            ),
            ThreatIntelConsumerAction::ShadowOnly
        );
    }

    #[test]
    fn iteration34_classify_consumer_action_raw_compatibility_always_raw() {
        let actionable = Some(ThreatIntelPolicyDecision::Actionable(
            ThreatIntelPolicyEvidence {
                intel_id: "test".to_string(),
                advisory_key: "key".to_string(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            },
        ));
        assert_eq!(
            classify_consumer_action(
                actionable.as_ref(),
                ThreatIntelConsumerKind::RawCompatibility,
                ThreatIntelDeferredMode::FailOpenNoAction,
            ),
            ThreatIntelConsumerAction::RawCompatibilityOnly
        );
    }

    #[test]
    fn iteration34_classify_consumer_action_advisory_cache_suppresses() {
        let actionable = Some(ThreatIntelPolicyDecision::Actionable(
            ThreatIntelPolicyEvidence {
                intel_id: "test".to_string(),
                advisory_key: "key".to_string(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            },
        ));
        assert_eq!(
            classify_consumer_action(
                actionable.as_ref(),
                ThreatIntelConsumerKind::AdvisoryCache,
                ThreatIntelDeferredMode::FailOpenNoAction,
            ),
            ThreatIntelConsumerAction::SuppressAction
        );
    }

    #[test]
    fn iteration34_classify_consumer_action_enforcement_actionable_permits() {
        let actionable = Some(ThreatIntelPolicyDecision::Actionable(
            ThreatIntelPolicyEvidence {
                intel_id: "test".to_string(),
                advisory_key: "key".to_string(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            },
        ));
        assert_eq!(
            classify_consumer_action(
                actionable.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::FailOpenNoAction,
            ),
            ThreatIntelConsumerAction::PermitAction
        );
    }

    #[test]
    fn iteration34_classify_consumer_action_enforcement_advisory_only_suppresses() {
        let advisory_only = Some(ThreatIntelPolicyDecision::AdvisoryOnly(
            ThreatIntelPolicyEvidence {
                intel_id: "test".to_string(),
                advisory_key: "key".to_string(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Unavailable,
                record_signature_valid: true,
            },
        ));
        assert_eq!(
            classify_consumer_action(
                advisory_only.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::FailOpenNoAction,
            ),
            ThreatIntelConsumerAction::SuppressAction
        );
    }

    #[test]
    fn iteration34_classify_consumer_action_enforcement_not_actionable_suppresses() {
        let not_actionable = Some(ThreatIntelPolicyDecision::NotActionable(
            ThreatIntelPolicyRejectReason::AdvisoryMissing,
        ));
        assert_eq!(
            classify_consumer_action(
                not_actionable.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::FailOpenNoAction,
            ),
            ThreatIntelConsumerAction::SuppressAction
        );
    }

    #[test]
    fn iteration34_classify_consumer_action_enforcement_deferred_suppresses() {
        let deferred = Some(ThreatIntelPolicyDecision::Deferred(
            ThreatIntelPolicyDeferReason::CanonicalUnavailable,
        ));
        assert_eq!(
            classify_consumer_action(
                deferred.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::FailOpenNoAction,
            ),
            ThreatIntelConsumerAction::SuppressAction
        );
    }

    #[test]
    fn iteration34_classify_consumer_action_enforcement_none_suppresses() {
        // Missing policy context must NOT silently permit enforcement.
        assert_eq!(
            classify_consumer_action(
                None,
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::FailOpenNoAction,
            ),
            ThreatIntelConsumerAction::SuppressAction
        );
    }

    #[test]
    fn iteration34_strict_dht_lookup_returns_none_without_context() {
        let manager = create_test_manager();
        // No policy context configured → strict returns None
        assert!(manager
            .lookup_threat_indicator_policy_strict("1.2.3.4", ThreatType::IpBlock)
            .is_none());
    }

    #[test]
    fn iteration34_strict_local_lookup_returns_none_without_context() {
        let manager = create_test_manager();
        // No policy context configured → strict returns None
        assert!(manager
            .lookup_local_indicator_policy_strict("1.2.3.4", ThreatType::IpBlock)
            .is_none());
    }

    #[test]
    fn iteration34_strict_ip_lookup_returns_none_without_context() {
        let manager = create_test_manager();
        // No policy context configured → strict returns None
        assert!(manager
            .lookup_local_indicator_by_ip_policy_strict("1.2.3.4")
            .is_none());
    }

    #[test]
    fn iteration34_legacy_composed_lookup_falls_back_without_context() {
        let manager = create_test_manager();
        // Legacy composed lookup falls back to raw when no context
        // (raw also returns None since transport is None, but the point is it doesn't panic)
        let _ = manager.lookup_threat_indicator_policy_composed("1.2.3.4", ThreatType::IpBlock);
        let _ = manager.lookup_local_indicator_policy_composed("1.2.3.4", ThreatType::IpBlock);
        let _ = manager.lookup_local_indicator_by_ip_policy_composed("1.2.3.4");
    }

    #[test]
    fn iteration34_handle_incoming_threat_stores_indicator_without_enforcement_when_no_context() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        let mut indicator =
            create_test_indicator("10.0.0.1", ThreatType::IpBlock, ThreatSeverity::High);
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        // Block store is disabled in test manager, but the enforcement gate
        // also suppresses when no policy context is configured.
        let accepted = manager.handle_incoming_threat(
            indicator.clone(),
            "remote-node",
            MeshNodeRole::EDGE,
            None,
        );

        // Should be accepted for storage/bookkeeping even without enforcement.
        assert!(accepted);

        // Verify the indicator was stored locally.
        let stored = manager.lookup_local_indicator("10.0.0.1", ThreatType::IpBlock);
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().indicator_value, "10.0.0.1");
    }

    #[test]
    fn iteration34_apply_sync_stores_indicators_without_enforcement_when_no_context() {
        let manager = create_test_manager();
        manager.register_peer("sync-node".to_string(), MeshNodeRole::GLOBAL);
        let now = synvoid_utils::safe_unix_timestamp();
        let mut ind1 = create_test_indicator("10.0.0.2", ThreatType::IpBlock, ThreatSeverity::High);
        ind1.timestamp = now;
        ind1.ttl_seconds = 3600;
        let mut ind2 = create_test_indicator(
            "10.0.0.3",
            ThreatType::RateLimitViolation,
            ThreatSeverity::Medium,
        );
        ind2.timestamp = now;
        ind2.ttl_seconds = 3600;
        let indicators = vec![ind1, ind2];

        let removed = manager.apply_sync(indicators, "sync-node", MeshNodeRole::GLOBAL, None);

        // All indicators should be accepted (stored), none removed.
        assert!(removed.is_empty());

        // Verify indicators were stored locally.
        assert!(manager
            .lookup_local_indicator("10.0.0.2", ThreatType::IpBlock)
            .is_some());
        assert!(manager
            .lookup_local_indicator("10.0.0.3", ThreatType::RateLimitViolation)
            .is_some());
    }

    #[test]
    fn iteration34_handle_hot_threat_gossip_stores_indicator_without_enforcement() {
        let manager = create_test_manager();
        manager.register_peer("gossip".to_string(), MeshNodeRole::EDGE);
        let mut indicator =
            create_test_indicator("10.0.0.4", ThreatType::IpBlock, ThreatSeverity::Critical);
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        manager.handle_hot_threat_gossip(
            Vec::new(),
            0,
            synvoid_utils::safe_unix_timestamp(),
            Some(indicator),
        );

        // The gossip delegates to handle_incoming_threat which stores the
        // indicator but suppresses enforcement without policy context.
        let stored = manager.lookup_local_indicator("10.0.0.4", ThreatType::IpBlock);
        assert!(stored.is_some());
    }

    #[test]
    fn iteration34_enforcement_gate_suppresses_ip_block_when_no_context() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        let mut indicator =
            create_test_indicator("10.0.0.5", ThreatType::IpBlock, ThreatSeverity::High);
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        let accepted =
            manager.handle_incoming_threat(indicator, "remote-node", MeshNodeRole::EDGE, None);

        assert!(accepted);
        // Block store is disabled in test AND enforcement is suppressed.
        // Verify the block store was NOT called (entry should not exist).
        let entries = manager.block_store.get_all_entries();
        assert!(entries.is_empty());
    }

    #[test]
    fn iteration34_enforcement_gate_supresses_rate_limit_when_no_context() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        let mut indicator = create_test_indicator(
            "10.0.0.6",
            ThreatType::RateLimitViolation,
            ThreatSeverity::Medium,
        );
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        let accepted =
            manager.handle_incoming_threat(indicator, "remote-node", MeshNodeRole::EDGE, None);

        assert!(accepted);
        let entries = manager.block_store.get_all_entries();
        assert!(entries.is_empty());
    }

    #[test]
    fn iteration34_enforcement_gate_suppresses_suspicious_when_no_context() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        let mut indicator = create_test_indicator(
            "10.0.0.7",
            ThreatType::SuspiciousActivity,
            ThreatSeverity::High,
        );
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        let accepted =
            manager.handle_incoming_threat(indicator, "remote-node", MeshNodeRole::EDGE, None);

        assert!(accepted);
        let entries = manager.block_store.get_all_entries();
        assert!(entries.is_empty());
    }

    #[test]
    fn iteration34_enforcement_gate_suppresses_ip_throttle_when_no_context() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        let mut indicator =
            create_test_indicator("10.0.0.8", ThreatType::IpThrottle, ThreatSeverity::Medium);
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        let accepted =
            manager.handle_incoming_threat(indicator, "remote-node", MeshNodeRole::EDGE, None);

        assert!(accepted);
        let entries = manager.block_store.get_all_entries();
        assert!(entries.is_empty());
    }

    #[test]
    fn iteration34_regression_raw_indicator_no_canonical_no_block_mutation() {
        // Core regression test: a raw indicator from mesh without canonical trust
        // must NOT cause block store mutation via the enforcement path.
        let manager = create_test_manager();
        manager.register_peer("untrusted-mesh-node".to_string(), MeshNodeRole::EDGE);
        let mut indicator = create_test_indicator(
            "192.168.100.1",
            ThreatType::IpBlock,
            ThreatSeverity::Critical,
        );
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 7200;

        let accepted = manager.handle_incoming_threat(
            indicator,
            "untrusted-mesh-node",
            MeshNodeRole::EDGE,
            None,
        );

        // Stored for bookkeeping.
        assert!(accepted);
        // No enforcement occurred.
        assert!(manager.block_store.get_all_entries().is_empty());
        // Local lookup finds it (bookkeeping path).
        assert!(manager
            .lookup_local_indicator("192.168.100.1", ThreatType::IpBlock)
            .is_some());
        // But strict lookup returns None (no policy context).
        assert!(manager
            .lookup_local_indicator_by_ip_policy_strict("192.168.100.1")
            .is_none());
    }

    #[test]
    fn iteration34_classify_consumer_action_enforcement_with_fail_closed_mode() {
        let deferred = Some(ThreatIntelPolicyDecision::Deferred(
            ThreatIntelPolicyDeferReason::CanonicalUnavailable,
        ));
        // Even with FailClosedNoAction mode, Deferred still suppresses
        // (the mode is for future extension; current behavior is always suppress).
        assert_eq!(
            classify_consumer_action(
                deferred.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::FailClosedNoAction,
            ),
            ThreatIntelConsumerAction::SuppressAction
        );
    }

    #[test]
    fn iteration34_classify_consumer_action_enforcement_with_shadow_mode() {
        let actionable = Some(ThreatIntelPolicyDecision::Actionable(
            ThreatIntelPolicyEvidence {
                intel_id: "test".to_string(),
                advisory_key: "key".to_string(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            },
        ));
        // Even when actionable, ShadowOnly deferred mode does not change
        // the enforcement kind behavior (consumer kind dominates).
        assert_eq!(
            classify_consumer_action(
                actionable.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::ShadowOnly,
            ),
            ThreatIntelConsumerAction::PermitAction
        );
    }

    #[test]
    fn iteration34_evaluate_incoming_threat_policy_returns_suppress_without_context() {
        let manager = create_test_manager();
        let gate = manager.evaluate_incoming_threat_policy("1.2.3.4", ThreatType::IpBlock);
        // No policy context → SuppressAction
        assert_eq!(gate.action, ThreatIntelConsumerAction::SuppressAction);
        assert!(gate.decision.is_none());
    }

    // ---------------------------------------------------------------------------
    // Iteration 35: Semantic cleanup tests
    // ---------------------------------------------------------------------------

    // Test: record_enforcement_suppression_metric classifies decisions correctly.
    #[test]
    fn iteration35_suppression_metric_classifier_not_configured() {
        // None → not_configured metric (already tested implicitly, but explicit here).
        record_enforcement_suppression_metric(&None);
        // No panic = metric recorded. Stub metrics are no-ops; this tests the match arms.
    }

    #[test]
    fn iteration35_suppression_metric_classifier_advisory_only() {
        let decision = Some(ThreatIntelPolicyDecision::AdvisoryOnly(
            ThreatIntelPolicyEvidence {
                intel_id: "test".to_string(),
                advisory_key: "key".to_string(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            },
        ));
        record_enforcement_suppression_metric(&decision);
    }

    #[test]
    fn iteration35_suppression_metric_classifier_not_actionable() {
        let decision = Some(ThreatIntelPolicyDecision::NotActionable(
            ThreatIntelPolicyRejectReason::AdvisoryMissing,
        ));
        record_enforcement_suppression_metric(&decision);
    }

    #[test]
    fn iteration35_suppression_metric_classifier_deferred() {
        let decision = Some(ThreatIntelPolicyDecision::Deferred(
            ThreatIntelPolicyDeferReason::CanonicalUnavailable,
        ));
        record_enforcement_suppression_metric(&decision);
    }

    #[test]
    fn iteration35_suppression_metric_classifier_actionable_no_suppression() {
        let decision = Some(ThreatIntelPolicyDecision::Actionable(
            ThreatIntelPolicyEvidence {
                intel_id: "test".to_string(),
                advisory_key: "key".to_string(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            },
        ));
        // Actionable decisions should not record any suppression metric.
        record_enforcement_suppression_metric(&decision);
    }

    // Test: classify_consumer_action deferred mode dispatch.
    #[test]
    fn iteration35_deferred_mode_fail_open_no_action_suppresses() {
        let deferred = Some(ThreatIntelPolicyDecision::Deferred(
            ThreatIntelPolicyDeferReason::CanonicalUnavailable,
        ));
        assert_eq!(
            classify_consumer_action(
                deferred.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::FailOpenNoAction,
            ),
            ThreatIntelConsumerAction::SuppressAction
        );
    }

    #[test]
    fn iteration35_deferred_mode_fail_closed_no_action_suppresses() {
        let deferred = Some(ThreatIntelPolicyDecision::Deferred(
            ThreatIntelPolicyDeferReason::CanonicalUnknown,
        ));
        assert_eq!(
            classify_consumer_action(
                deferred.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::FailClosedNoAction,
            ),
            ThreatIntelConsumerAction::SuppressAction
        );
    }

    #[test]
    fn iteration35_deferred_mode_shadow_only_returns_shadow() {
        let deferred = Some(ThreatIntelPolicyDecision::Deferred(
            ThreatIntelPolicyDeferReason::AdvisoryUnavailable,
        ));
        assert_eq!(
            classify_consumer_action(
                deferred.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::ShadowOnly,
            ),
            ThreatIntelConsumerAction::ShadowOnly
        );
    }

    #[test]
    fn iteration35_deferred_mode_shadow_only_does_not_permit_action() {
        // Even in ShadowOnly deferred mode, Actionable decisions still permit.
        let actionable = Some(ThreatIntelPolicyDecision::Actionable(
            ThreatIntelPolicyEvidence {
                intel_id: "test".to_string(),
                advisory_key: "key".to_string(),
                advisory_status: AdvisoryRecordStatus::Present,
                advisory_freshness: AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            },
        ));
        assert_eq!(
            classify_consumer_action(
                actionable.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                ThreatIntelDeferredMode::ShadowOnly,
            ),
            ThreatIntelConsumerAction::PermitAction
        );
    }

    #[test]
    fn iteration35_missing_context_suppresses_regardless_of_deferred_mode() {
        // None decision → always SuppressAction regardless of deferred mode.
        for mode in [
            ThreatIntelDeferredMode::FailOpenNoAction,
            ThreatIntelDeferredMode::FailClosedNoAction,
            ThreatIntelDeferredMode::ShadowOnly,
        ] {
            assert_eq!(
                classify_consumer_action(None, ThreatIntelConsumerKind::Enforcement, mode),
                ThreatIntelConsumerAction::SuppressAction,
                "missing context must suppress with deferred mode {:?}",
                mode
            );
        }
    }

    // Test: ASN block is observational — does not produce block store mutation.
    #[test]
    fn iteration35_asn_block_observational_no_block_mutation() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        let mut indicator =
            create_test_indicator("64496", ThreatType::AsnBlock, ThreatSeverity::High);
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        let accepted =
            manager.handle_incoming_threat(indicator, "remote-node", MeshNodeRole::EDGE, None);

        assert!(accepted);
        // ASN block is observational — no block store mutation.
        assert!(manager.block_store.get_all_entries().is_empty());
    }

    // Test: Strict lookups return None when no policy context.
    #[test]
    fn iteration35_strict_lookup_returns_none_without_context() {
        let manager = create_test_manager();
        assert!(manager
            .lookup_threat_indicator_policy_strict(TEST_IP, ThreatType::IpBlock)
            .is_none());
        assert!(manager
            .lookup_local_indicator_policy_strict(TEST_IP, ThreatType::IpBlock)
            .is_none());
        assert!(manager
            .lookup_local_indicator_by_ip_policy_strict(TEST_IP)
            .is_none());
    }

    // Test: Raw/compatibility lookups still return records where expected.
    #[test]
    fn iteration35_raw_lookup_still_returns_records() {
        let manager = create_test_manager();
        manager.register_peer("test-node".to_string(), MeshNodeRole::GLOBAL);
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: TEST_IP.to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            source_node_id: "test-node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            site_scope: "".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };
        manager.handle_incoming_threat(indicator, "test-node", MeshNodeRole::GLOBAL, None);
        // Raw lookup returns the indicator.
        assert!(manager
            .lookup_local_indicator(TEST_IP, ThreatType::IpBlock)
            .is_some());
    }

    // Test: Hot-threat gossip and apply_sync inherit the enforcement gate.
    #[test]
    fn iteration35_hot_threat_gossip_inherits_enforcement_gate() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        let mut indicator =
            create_test_indicator("10.0.0.99", ThreatType::IpBlock, ThreatSeverity::Critical);
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        // Simulate what handle_hot_threat_gossip does: delegate to handle_incoming_threat.
        let accepted =
            manager.handle_incoming_threat(indicator, "remote-node", MeshNodeRole::EDGE, None);
        assert!(accepted);
        // No policy context → enforcement suppressed.
        assert!(manager.block_store.get_all_entries().is_empty());
    }

    #[test]
    fn iteration35_apply_sync_inherits_enforcement_gate() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        let indicators = vec![{
            let mut ind = create_test_indicator(
                "10.0.0.100",
                ThreatType::RateLimitViolation,
                ThreatSeverity::Medium,
            );
            ind.timestamp = synvoid_utils::safe_unix_timestamp();
            ind.ttl_seconds = 3600;
            ind
        }];

        // apply_sync delegates to handle_incoming_threat per indicator.
        let removed = manager.apply_sync(indicators, "remote-node", MeshNodeRole::EDGE, None);
        // Indicator was accepted (stored for bookkeeping), so no removed keys.
        assert!(removed.is_empty());
        // No policy context → enforcement suppressed.
        assert!(manager.block_store.get_all_entries().is_empty());
    }

    // Test: Advisory-only rate-limit does not mutate block store.
    #[test]
    fn iteration35_advisory_only_rate_limit_no_mutation() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        // Set up policy context with advisory present but canonical not trusted.
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical_no_trust = TestCanonicalReader::new(CanonicalFreshness::Live);
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical_no_trust),
            Arc::new(advisory),
        )));

        let mut indicator = create_test_indicator(
            TEST_IP,
            ThreatType::RateLimitViolation,
            ThreatSeverity::Medium,
        );
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        let accepted =
            manager.handle_incoming_threat(indicator, "remote-node", MeshNodeRole::EDGE, None);
        assert!(accepted);
        // Advisory-only → enforcement suppressed → no block store mutation.
        assert!(manager.block_store.get_all_entries().is_empty());
    }

    // Test: Advisory-only suspicious activity does not mutate block store.
    #[test]
    fn iteration35_advisory_only_suspicious_no_mutation() {
        let manager = create_test_manager();
        manager.register_peer("remote-node".to_string(), MeshNodeRole::EDGE);
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical_no_trust = TestCanonicalReader::new(CanonicalFreshness::Live);
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical_no_trust),
            Arc::new(advisory),
        )));

        let mut indicator = create_test_indicator(
            TEST_IP,
            ThreatType::SuspiciousActivity,
            ThreatSeverity::High,
        );
        indicator.timestamp = synvoid_utils::safe_unix_timestamp();
        indicator.ttl_seconds = 3600;

        let accepted =
            manager.handle_incoming_threat(indicator, "remote-node", MeshNodeRole::EDGE, None);
        assert!(accepted);
        assert!(manager.block_store.get_all_entries().is_empty());
    }

    // Test: IncomingThreatPolicyGate carries the decision.
    #[test]
    fn iteration35_policy_gate_carries_decision() {
        let manager = create_test_manager();
        let gate = manager.evaluate_incoming_threat_policy(TEST_IP, ThreatType::IpBlock);
        // No context → action is Suppress, decision is None.
        assert_eq!(gate.action, ThreatIntelConsumerAction::SuppressAction);
        assert!(gate.decision.is_none());
    }

    #[test]
    fn iteration35_policy_gate_with_context_carries_decision() {
        let manager = create_test_manager();
        let advisory =
            TestAdvisorySource::new().with_record(TEST_KEY, test_advisory_record(TEST_KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            TEST_IP,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );
        manager.set_policy_context(Some(ThreatIntelPolicyContext::new(
            Arc::new(canonical),
            Arc::new(advisory),
        )));

        let gate = manager.evaluate_incoming_threat_policy(TEST_IP, ThreatType::IpBlock);
        assert_eq!(gate.action, ThreatIntelConsumerAction::PermitAction);
        assert!(matches!(
            gate.decision,
            Some(ThreatIntelPolicyDecision::Actionable(_))
        ));
    }
}
